package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Configuration
const (
	TargetGateway         = "192.168.1.1" // Fallback
	TCPServerIP           = "203.57.51.217"
	TCPServerPort         = "9999"
	Interval              = 250 * time.Millisecond
	LogDir                = "network_logs"
	SlowCheckInterval     = 10 * time.Second
	MaxConsecutiveFailures = 2
	DisplayUpdateInterval = 1 * time.Second
	TCPTimeout            = 1 * time.Second
	ICMPTimeout           = 250 * time.Millisecond
)

var PublicIPs = []string{"1.1.1.1", "8.8.8.8"}

type LatencyStats struct {
	values []float64
	mu     sync.Mutex
}

func (ls *LatencyStats) Add(val float64) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.values = append(ls.values, val)
	if len(ls.values) > 100 {
		ls.values = ls.values[1:]
	}
}

func (ls *LatencyStats) GetStats() (avg, min, max float64, hasData bool) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.values) == 0 {
		return 0, 0, 0, false
	}
	sum := 0.0
	min = ls.values[0]
	max = ls.values[0]
	for _, v := range ls.values {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return sum / float64(len(ls.values)), min, max, true
}

type NetworkMonitor struct {
	// State
	prevRouterOK   bool
	prevPublicOK   bool
	prevTCPOK      bool
	lastKnownIP    string
	lastKnownSSID  string
	prevDNSOK      *bool
	
	// Dropout tracking
	dropoutCount       int
	lastDropoutStart   time.Time
	isCurrentlyDropped bool
	failureStreak      int
	
	// Latency tracking
	routerLatencies LatencyStats
	publicLatencies LatencyStats
	tcpLatencies    LatencyStats
	
	// Current readings
	currentRouterRTT *float64
	currentPublicRTT *float64
	currentTCPRTT    *float64
	currentRouterOK  bool
	currentPublicOK  bool
	currentTCPOK     bool
	
	// Timing
	lastSlowCheck     time.Time
	lastDisplayUpdate time.Time
	
	// System
	gatewayIP     string
	recentEvents  []string
	eventsMu      sync.Mutex
	
	// Logging
	logFile         *csv.Writer
	detailedLogFile *csv.Writer
	dropoutLogFile  *csv.Writer
	logFileFP       *os.File
	detailedLogFP   *os.File
	dropoutLogFP    *os.File
}

func NewNetworkMonitor() *NetworkMonitor {
	return &NetworkMonitor{
		prevRouterOK:      true,
		prevPublicOK:      true,
		prevTCPOK:         true,
		gatewayIP:         TargetGateway,
		recentEvents:      make([]string, 0, 50),
		lastSlowCheck:     time.Now(),
		lastDisplayUpdate: time.Now(),
	}
}

func (nm *NetworkMonitor) logEvent(message string) {
	nm.eventsMu.Lock()
	defer nm.eventsMu.Unlock()
	timestamp := time.Now().Format("15:04:05.000")
	event := fmt.Sprintf("[%s] %s", timestamp, message)
	nm.recentEvents = append(nm.recentEvents, event)
	if len(nm.recentEvents) > 50 {
		nm.recentEvents = nm.recentEvents[1:]
	}
}

func (nm *NetworkMonitor) getDefaultGateway() string {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print", "0.0.0.0")
		output, err := cmd.Output()
		if err != nil {
			return ""
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					return fields[2]
				}
			}
		}
	case "darwin":
		cmd := exec.Command("route", "-n", "get", "default")
		output, err := cmd.Output()
		if err != nil {
			return ""
		}
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "gateway:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	case "linux":
		cmd := exec.Command("ip", "route", "show", "default")
		output, err := cmd.Output()
		if err != nil {
			return ""
		}
		fields := strings.Fields(string(output))
		if len(fields) >= 3 && fields[0] == "default" {
			return fields[2]
		}
	}
	return ""
}

func tcpPing(host, port string, timeout time.Duration) (bool, *float64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	
	elapsed := time.Since(start).Seconds() * 1000 // Convert to ms
	return true, &elapsed
}

func icmpPingSimple(host string, timeout time.Duration) (bool, *float64) {
	// Simple TCP connection test as fallback for ICMP
	// Using a common port (80 for HTTP)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "80"), timeout)
	if err != nil {
		// Try pinging using system ping command
		return systemPing(host, timeout)
	}
	defer conn.Close()
	
	elapsed := time.Since(start).Seconds() * 1000
	return true, &elapsed
}

func systemPing(host string, timeout time.Duration) (bool, *float64) {
	var cmd *exec.Cmd
	start := time.Now()
	
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), host)
	case "darwin", "linux":
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%.0f", timeout.Seconds()), host)
	default:
		return false, nil
	}
	
	err := cmd.Run()
	elapsed := time.Since(start).Seconds() * 1000
	
	if err != nil {
		return false, nil
	}
	return true, &elapsed
}

func (nm *NetworkMonitor) getPublicIP() string {
	client := &http.Client{Timeout: 2 * time.Second}
	services := []string{
		"https://api.ipify.org?format=json",
		"https://api.myip.com",
	}
	
	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}
			
			var result map[string]interface{}
			if err := json.Unmarshal(body, &result); err != nil {
				continue
			}
			
			if ip, ok := result["ip"].(string); ok {
				return ip
			}
			if ip, ok := result["ipAddress"].(string); ok {
				return ip
			}
		}
	}
	return ""
}

func (nm *NetworkMonitor) testDNS() bool {
	_, err := net.LookupHost("google.com")
	return err == nil
}

func (nm *NetworkMonitor) getSSID() string {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("netsh", "wlan", "show", "interfaces")
	case "darwin":
		cmd = exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I")
	case "linux":
		cmd = exec.Command("iwgetid", "-r")
	default:
		return ""
	}
	
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if runtime.GOOS == "windows" {
			if strings.Contains(line, "SSID") && !strings.Contains(line, "BSSID") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		} else if runtime.GOOS == "darwin" {
			if strings.Contains(line, " SSID:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					return strings.TrimSpace(parts[1])
				}
			}
		} else if runtime.GOOS == "linux" {
			return strings.TrimSpace(string(output))
		}
	}
	return ""
}

func (nm *NetworkMonitor) clearScreen() {
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func (nm *NetworkMonitor) drawStatsDisplay() {
	nm.clearScreen()
	
	status := "[OK] ONLINE"
	if !nm.currentRouterOK && !nm.currentPublicOK && !nm.currentTCPOK {
		status = "[X] OFFLINE"
	}
	
	if nm.isCurrentlyDropped {
		duration := time.Since(nm.lastDropoutStart).Seconds()
		status = fmt.Sprintf("[X] DROPOUT #%d (%.1fs)", nm.dropoutCount, duration)
	}
	
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("NETWORK MONITOR - %s\n", status)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()
	
	// Current Latencies
	fmt.Println("CURRENT LATENCY:")
	fmt.Printf("  Router (%s):%-20s", nm.gatewayIP, "")
	if nm.currentRouterOK && nm.currentRouterRTT != nil {
		color := "[OK]"
		if *nm.currentRouterRTT >= 50 {
			color = "[SLOW]"
		} else if *nm.currentRouterRTT >= 10 {
			color = "[WARN]"
		}
		fmt.Printf("%s %6.2fms\n", color, *nm.currentRouterRTT)
	} else {
		fmt.Println("[X] TIMEOUT")
	}
	
	fmt.Printf("  Public ICMP (Cloudflare/Google):%-6s", "")
	if nm.currentPublicOK && nm.currentPublicRTT != nil {
		color := "[OK]"
		if *nm.currentPublicRTT >= 100 {
			color = "[SLOW]"
		} else if *nm.currentPublicRTT >= 30 {
			color = "[WARN]"
		}
		fmt.Printf("%s %6.2fms\n", color, *nm.currentPublicRTT)
	} else {
		fmt.Println("[X] TIMEOUT")
	}
	
	fmt.Printf("  TCP Server (%s):%-16s", TCPServerIP, "")
	if nm.currentTCPOK && nm.currentTCPRTT != nil {
		color := "[OK]"
		if *nm.currentTCPRTT >= 150 {
			color = "[SLOW]"
		} else if *nm.currentTCPRTT >= 50 {
			color = "[WARN]"
		}
		fmt.Printf("%s %6.2fms\n", color, *nm.currentTCPRTT)
	} else {
		fmt.Println("[X] TIMEOUT")
	}
	fmt.Println()
	
	// Statistics
	fmt.Println("STATISTICS (last 100 successful pings):")
	if avg, min, max, ok := nm.routerLatencies.GetStats(); ok {
		fmt.Printf("  Router:%-26savg=%5.1fms  min=%5.1fms  max=%5.1fms\n", "", avg, min, max)
	}
	if avg, min, max, ok := nm.publicLatencies.GetStats(); ok {
		fmt.Printf("  Public ICMP:%-20savg=%5.1fms  min=%5.1fms  max=%5.1fms\n", "", avg, min, max)
	}
	if avg, min, max, ok := nm.tcpLatencies.GetStats(); ok {
		fmt.Printf("  TCP Server:%-21savg=%5.1fms  min=%5.1fms  max=%5.1fms\n", "", avg, min, max)
	}
	fmt.Println()
	
	// Connection Info
	fmt.Println("CONNECTION INFO:")
	if nm.lastKnownSSID != "" {
		fmt.Printf("  WiFi SSID: %s\n", nm.lastKnownSSID)
	}
	if nm.lastKnownIP != "" {
		fmt.Printf("  Public IP: %s\n", nm.lastKnownIP)
	}
	fmt.Printf("  Total Dropouts: %d\n", nm.dropoutCount)
	fmt.Println()
	
	// Recent Events
	fmt.Println("RECENT EVENTS:")
	fmt.Println(strings.Repeat("-", 80))
	nm.eventsMu.Lock()
	if len(nm.recentEvents) == 0 {
		fmt.Println("  No events yet...")
	} else {
		start := len(nm.recentEvents) - 15
		if start < 0 {
			start = 0
		}
		for i := start; i < len(nm.recentEvents); i++ {
			fmt.Println(nm.recentEvents[i])
		}
	}
	nm.eventsMu.Unlock()
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop monitoring")
}

func (nm *NetworkMonitor) initResources() error {
	// Create log directory
	if err := os.MkdirAll(LogDir, 0755); err != nil {
		return err
	}
	
	// Detect gateway
	if gw := nm.getDefaultGateway(); gw != "" {
		nm.gatewayIP = gw
		nm.logEvent(fmt.Sprintf("[+] Auto-Detected Gateway: %s", nm.gatewayIP))
	} else {
		nm.logEvent(fmt.Sprintf("[!] Could not detect gateway. Using fallback: %s", nm.gatewayIP))
	}
	
	// Open log files
	timestamp := time.Now().Format("20060102_150405")
	
	var err error
	nm.logFileFP, err = os.Create(fmt.Sprintf("%s/%s_connection_log.csv", LogDir, timestamp))
	if err != nil {
		return err
	}
	nm.logFile = csv.NewWriter(nm.logFileFP)
	
	nm.detailedLogFP, err = os.Create(fmt.Sprintf("%s/%s_connection_detailed_log.csv", LogDir, timestamp))
	if err != nil {
		return err
	}
	nm.detailedLogFile = csv.NewWriter(nm.detailedLogFP)
	
	nm.dropoutLogFP, err = os.Create(fmt.Sprintf("%s/%s_dropouts.csv", LogDir, timestamp))
	if err != nil {
		return err
	}
	nm.dropoutLogFile = csv.NewWriter(nm.dropoutLogFP)
	
	// Write headers
	nm.logFile.Write([]string{"Timestamp", "RouterReachable", "InternetReachable", "TCPReachable",
		"DNS", "PublicIPChange", "SSIDChange", "DropoutNumber"})
	nm.logFile.Flush()
	
	nm.detailedLogFile.Write([]string{"Timestamp", "RouterStatus", "RouterRTT",
		"PublicPingSuccess", "PublicPingTotal", "AvgPublicRTT",
		"TCPStatus", "TCPRTT", "DNSResolution", "PublicIP", "SSID", "DropoutNumber", "Notes"})
	nm.detailedLogFile.Flush()
	
	nm.dropoutLogFile.Write([]string{"DropoutNumber", "StartTime", "EndTime", "Duration",
		"RouterFailed", "InternetFailed", "TCPFailed", "RecoveryMethod"})
	nm.dropoutLogFile.Flush()
	
	return nil
}

func (nm *NetworkMonitor) closeResources() {
	if nm.logFile != nil {
		nm.logFile.Flush()
		nm.logFileFP.Close()
	}
	if nm.detailedLogFile != nil {
		nm.detailedLogFile.Flush()
		nm.detailedLogFP.Close()
	}
	if nm.dropoutLogFile != nil {
		nm.dropoutLogFile.Flush()
		nm.dropoutLogFP.Close()
	}
}

func (nm *NetworkMonitor) Monitor() error {
	if err := nm.initResources(); err != nil {
		return err
	}
	defer nm.closeResources()
	
	// Initial slow checks
	nm.lastKnownIP = nm.getPublicIP()
	nm.lastKnownSSID = nm.getSSID()
	
	if nm.lastKnownIP != "" {
		nm.logEvent(fmt.Sprintf("[IP] Initial IP: %s", nm.lastKnownIP))
	}
	if nm.lastKnownSSID != "" {
		nm.logEvent(fmt.Sprintf("[WIFI] Initial SSID: %s", nm.lastKnownSSID))
	}
	
	nm.drawStatsDisplay()
	
	// Setup signal handler
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-sigChan:
			return nm.shutdown()
		case <-ticker.C:
			nm.runCheck()
		}
	}
}

func (nm *NetworkMonitor) runCheck() {
	loopStart := time.Now()
	timestamp := loopStart.Format("2006-01-02 15:04:05.000")
	
	// Fast checks - run concurrently
	type pingResult struct {
		ok  bool
		rtt *float64
	}
	
	routerChan := make(chan pingResult, 1)
	tcpChan := make(chan pingResult, 1)
	publicChans := make([]chan pingResult, len(PublicIPs))
	
	// Router ping
	go func() {
		ok, rtt := systemPing(nm.gatewayIP, ICMPTimeout)
		routerChan <- pingResult{ok, rtt}
	}()
	
	// TCP ping
	go func() {
		ok, rtt := tcpPing(TCPServerIP, TCPServerPort, TCPTimeout)
		tcpChan <- pingResult{ok, rtt}
	}()
	
	// Public pings
	for i, ip := range PublicIPs {
		publicChans[i] = make(chan pingResult, 1)
		go func(ip string, ch chan pingResult) {
			ok, rtt := systemPing(ip, ICMPTimeout)
			ch <- pingResult{ok, rtt}
		}(ip, publicChans[i])
	}
	
	// Collect results
	routerResult := <-routerChan
	tcpResult := <-tcpChan
	
	publicResults := make([]pingResult, len(PublicIPs))
	for i := range PublicIPs {
		publicResults[i] = <-publicChans[i]
	}
	
	// Process results
	nm.currentRouterOK = routerResult.ok
	nm.currentRouterRTT = routerResult.rtt
	if routerResult.ok && routerResult.rtt != nil {
		nm.routerLatencies.Add(*routerResult.rtt)
	}
	
	nm.currentTCPOK = tcpResult.ok
	nm.currentTCPRTT = tcpResult.rtt
	if tcpResult.ok && tcpResult.rtt != nil {
		nm.tcpLatencies.Add(*tcpResult.rtt)
	}
	
	publicSuccess := 0
	var publicRTTs []float64
	for _, res := range publicResults {
		if res.ok {
			publicSuccess++
			if res.rtt != nil {
				publicRTTs = append(publicRTTs, *res.rtt)
			}
		}
	}
	
	nm.currentPublicOK = publicSuccess > 0
	if len(publicRTTs) > 0 {
		sum := 0.0
		for _, rtt := range publicRTTs {
			sum += rtt
		}
		avg := sum / float64(len(publicRTTs))
		nm.currentPublicRTT = &avg
		nm.publicLatencies.Add(avg)
	} else {
		nm.currentPublicRTT = nil
	}
	
	// Slow checks
	ipChanged := false
	ssidChanged := false
	currentIP := nm.lastKnownIP
	currentSSID := nm.lastKnownSSID
	
	if time.Since(nm.lastSlowCheck) >= SlowCheckInterval {
		nm.lastSlowCheck = loopStart
		
		dnsOK := nm.testDNS()
		nm.prevDNSOK = &dnsOK
		
		if fetchedIP := nm.getPublicIP(); fetchedIP != "" {
			if nm.lastKnownIP != "" && fetchedIP != nm.lastKnownIP {
				ipChanged = true
				nm.logEvent(fmt.Sprintf("[!] PUBLIC IP CHANGED: %s -> %s", nm.lastKnownIP, fetchedIP))
			}
			nm.lastKnownIP = fetchedIP
			currentIP = fetchedIP
		}
		
		if fetchedSSID := nm.getSSID(); fetchedSSID != "" && fetchedSSID != nm.lastKnownSSID {
			ssidChanged = true
			nm.logEvent(fmt.Sprintf("[WIFI] SSID CHANGED: %s -> %s", nm.lastKnownSSID, fetchedSSID))
			nm.lastKnownSSID = fetchedSSID
			currentSSID = fetchedSSID
		}
	}
	
	// Dropout logic
	var notes []string
	currentConnectionAlive := nm.currentRouterOK || nm.currentPublicOK || nm.currentTCPOK
	
	if !currentConnectionAlive {
		nm.failureStreak++
	} else {
		nm.failureStreak = 0
	}
	
	if !nm.isCurrentlyDropped {
		if nm.failureStreak >= MaxConsecutiveFailures {
			// Start of dropout
			nm.isCurrentlyDropped = true
			nm.dropoutCount++
			nm.lastDropoutStart = loopStart
			
			nm.logEvent(fmt.Sprintf("[X] DROPOUT #%d DETECTED", nm.dropoutCount))
			nm.logEvent(fmt.Sprintf("    Router: %s | Internet: %s | TCP: %s",
				boolToStatus(!nm.currentRouterOK), boolToStatus(!nm.currentPublicOK), boolToStatus(!nm.currentTCPOK)))
			notes = append(notes, "DROPOUT_STARTED")
		}
	} else {
		if currentConnectionAlive {
			// End of dropout
			nm.isCurrentlyDropped = false
			nm.failureStreak = 0
			duration := time.Since(nm.lastDropoutStart).Seconds()
			
			var recoveryMethod []string
			if nm.currentRouterOK {
				recoveryMethod = append(recoveryMethod, "ROUTER")
			}
			if nm.currentPublicOK {
				recoveryMethod = append(recoveryMethod, "PUBLIC")
			}
			if nm.currentTCPOK {
				recoveryMethod = append(recoveryMethod, "TCP")
			}
			recoveryStr := strings.Join(recoveryMethod, "+")
			
			nm.logEvent(fmt.Sprintf("[+] Connection recovered after %.2fs via %s", duration, recoveryStr))
			notes = append(notes, fmt.Sprintf("RECOVERED_%.2fs", duration))
			
			// Write dropout log
			nm.dropoutLogFile.Write([]string{
				fmt.Sprintf("%d", nm.dropoutCount),
				nm.lastDropoutStart.Format("2006-01-02 15:04:05.000"),
				timestamp,
				fmt.Sprintf("%.3f", duration),
				boolToYesNo(!nm.currentRouterOK),
				boolToYesNo(!nm.currentPublicOK),
				boolToYesNo(!nm.currentTCPOK),
				recoveryStr,
			})
			nm.dropoutLogFile.Flush()
		}
	}
	
	// Alert on individual failures
	if !nm.isCurrentlyDropped {
		if !nm.currentRouterOK && nm.prevRouterOK {
			nm.logEvent("[!] Router Unreachable")
			notes = append(notes, "ROUTER_DOWN")
		}
		if !nm.currentPublicOK && nm.prevPublicOK {
			nm.logEvent("[!] Internet Unreachable")
			notes = append(notes, "INTERNET_DOWN")
		}
		if !nm.currentTCPOK && nm.prevTCPOK {
			nm.logEvent("[!] TCP Server Unreachable")
			notes = append(notes, "TCP_DOWN")
		}
	}
	
	// Latency warnings
	if nm.currentRouterOK && nm.currentRouterRTT != nil && *nm.currentRouterRTT > 50 {
		notes = append(notes, fmt.Sprintf("HIGH_ROUTER_LAT_%.0fms", *nm.currentRouterRTT))
	}
	if nm.currentPublicRTT != nil && *nm.currentPublicRTT > 100 {
		notes = append(notes, fmt.Sprintf("HIGH_PUBLIC_LAT_%.0fms", *nm.currentPublicRTT))
	}
	if nm.currentTCPOK && nm.currentTCPRTT != nil && *nm.currentTCPRTT > 150 {
		notes = append(notes, fmt.Sprintf("HIGH_TCP_LAT_%.0fms", *nm.currentTCPRTT))
	}
	
	// Write logs
	dropoutNumStr := ""
	if nm.isCurrentlyDropped {
		dropoutNumStr = fmt.Sprintf("%d", nm.dropoutCount)
	}
	
	nm.logFile.Write([]string{
		timestamp,
		boolToOKFail(nm.currentRouterOK),
		boolToOKFail(nm.currentPublicOK),
		boolToOKFail(nm.currentTCPOK),
		boolToOKFail(nm.prevDNSOK != nil && *nm.prevDNSOK),
		fmt.Sprintf("%t", ipChanged),
		fmt.Sprintf("%t", ssidChanged),
		dropoutNumStr,
	})
	nm.logFile.Flush()
	
	avgPublicRTT := ""
	if nm.currentPublicRTT != nil {
		avgPublicRTT = fmt.Sprintf("%.2f", *nm.currentPublicRTT)
	}
	
	routerRTTStr := ""
	if nm.currentRouterRTT != nil {
		routerRTTStr = fmt.Sprintf("%.2f", *nm.currentRouterRTT)
	}
	
	tcpRTTStr := ""
	if nm.currentTCPRTT != nil {
		tcpRTTStr = fmt.Sprintf("%.2f", *nm.currentTCPRTT)
	}
	
	nm.detailedLogFile.Write([]string{
		timestamp,
		boolToOKFail(nm.currentRouterOK),
		routerRTTStr,
		fmt.Sprintf("%d", publicSuccess),
		fmt.Sprintf("%d", len(PublicIPs)),
		avgPublicRTT,
		boolToOKFail(nm.currentTCPOK),
		tcpRTTStr,
		boolToOKFail(nm.prevDNSOK != nil && *nm.prevDNSOK),
		currentIP,
		currentSSID,
		dropoutNumStr,
		strings.Join(notes, "; "),
	})
	nm.detailedLogFile.Flush()
	
	// Update previous state
	nm.prevRouterOK = nm.currentRouterOK
	nm.prevPublicOK = nm.currentPublicOK
	nm.prevTCPOK = nm.currentTCPOK
	
	// Update display
	if time.Since(nm.lastDisplayUpdate) >= DisplayUpdateInterval {
		nm.lastDisplayUpdate = loopStart
		nm.drawStatsDisplay()
	}
}

func (nm *NetworkMonitor) shutdown() error {
	nm.clearScreen()
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("MONITORING STOPPED")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\nSESSION SUMMARY:\n")
	fmt.Printf("  Total Dropouts: %d\n", nm.dropoutCount)
	
	if avg, min, max, ok := nm.routerLatencies.GetStats(); ok {
		fmt.Println("\nAverage Latencies:")
		fmt.Printf("   Router: %.1fms (min: %.1fms, max: %.1fms)\n", avg, min, max)
	}
	if avg, min, max, ok := nm.publicLatencies.GetStats(); ok {
		if avg == 0 {
			fmt.Println("\nAverage Latencies:")
		}
		fmt.Printf("   Public: %.1fms (min: %.1fms, max: %.1fms)\n", avg, min, max)
	}
	if avg, min, max, ok := nm.tcpLatencies.GetStats(); ok {
		fmt.Printf("   TCP Server: %.1fms (min: %.1fms, max: %.1fms)\n", avg, min, max)
	}
	
	fmt.Printf("\nLogs saved to: %s/\n", LogDir)
	fmt.Println()
	
	return nil
}

func boolToOKFail(b bool) string {
	if b {
		return "OK"
	}
	return "FAIL"
}

func boolToYesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

func boolToStatus(failed bool) string {
	if failed {
		return "FAIL"
	}
	return "OK"
}

func main() {
	monitor := NewNetworkMonitor()
	if err := monitor.Monitor(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}