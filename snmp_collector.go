package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// LLDPNeighbor represents an LLDP neighbor relationship
type LLDPNeighbor struct {
	LocalDevice        string `json:"local_device"`
	LocalPort          string `json:"local_port"`
	LocalPortSpeed     string `json:"local_port_speed,omitempty"`
	RemoteDevice       string `json:"remote_device"`
	RemotePort         string `json:"remote_port"`
	RemoteDescription  string `json:"remote_description"`
}

// LLDP-MIB OIDs (IEEE 802.1AB)
const (
	LLDP_REM_TABLE       = "1.0.8802.1.1.2.1.4.1.1"
	LLDP_REM_SYS_NAME    = "1.0.8802.1.1.2.1.4.1.1.9"
	LLDP_REM_PORT_ID     = "1.0.8802.1.1.2.1.4.1.1.7"
	LLDP_REM_PORT_DESC   = "1.0.8802.1.1.2.1.4.1.1.8"
	LLDP_LOC_PORT_DESC   = "1.0.8802.1.1.2.1.3.7.1.4"
	IF_NAME              = "1.3.6.1.2.1.31.1.1.1.1"
	IF_DESCR             = "1.3.6.1.2.1.2.2.1.2"
	IF_SPEED             = "1.3.6.1.2.1.2.2.1.5"      // ifSpeed (bits/sec)
	IF_HIGH_SPEED        = "1.3.6.1.2.1.31.1.1.1.15"  // ifHighSpeed (Mbps)
	SYS_NAME_OID         = "1.3.6.1.2.1.1.5.0"
)

func main() {
	// Command line flags
	host := flag.String("host", "", "SNMP host IP address")
	community := flag.String("community", "public", "SNMP community string")
	port := flag.Int("port", 161, "SNMP port")
	deviceName := flag.String("device", "", "Device hostname/name")
	testMode := flag.Bool("test", false, "Test connectivity only")
	flag.Parse()

	if *host == "" {
		fmt.Fprintf(os.Stderr, "Error: -host is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if *deviceName == "" {
		*deviceName = *host
	}

	// Setup SNMP connection
	snmp := &gosnmp.GoSNMP{
		Target:    *host,
		Port:      uint16(*port),
		Community: *community,
		Version:   gosnmp.Version2c,
		Timeout:   time.Duration(5) * time.Second,
		Retries:   2,
	}

	err := snmp.Connect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SNMP connection failed: %v\n", err)
		os.Exit(1)
	}
	defer snmp.Conn.Close()

	// Test mode - just check connectivity
	if *testMode {
		result, err := snmp.Get([]string{SYS_NAME_OID})
		if err != nil {
			fmt.Fprintf(os.Stderr, "SNMP GET failed: %v\n", err)
			os.Exit(1)
		}

		for _, variable := range result.Variables {
			sysName := string(variable.Value.([]byte))
			fmt.Printf("SNMP connection successful - sysName: %s\n", sysName)
		}
		os.Exit(0)
	}

	// Collect LLDP neighbors
	neighbors, err := collectLLDPNeighbors(snmp, *deviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LLDP collection failed: %v\n", err)
		os.Exit(1)
	}

	// Output as JSON
	output, err := json.MarshalIndent(neighbors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}

func collectLLDPNeighbors(snmp *gosnmp.GoSNMP, deviceName string) ([]LLDPNeighbor, error) {
	neighbors := []LLDPNeighbor{}

	// Get local port map
	portMap, err := getLocalPortMap(snmp)
	if err != nil {
		return nil, fmt.Errorf("failed to get local port map: %w", err)
	}

	// Get interface speeds (port number -> speed string)
	speedMap := getInterfaceSpeeds(snmp)

	// Walk remote system names
	remoteSystems, err := snmpWalk(snmp, LLDP_REM_SYS_NAME)
	if err != nil {
		return nil, fmt.Errorf("failed to walk remote systems: %w", err)
	}

	// Walk remote port IDs
	remotePorts, err := snmpWalk(snmp, LLDP_REM_PORT_ID)
	if err != nil {
		return nil, fmt.Errorf("failed to walk remote ports: %w", err)
	}

	// Walk remote port descriptions
	remoteDescs, err := snmpWalk(snmp, LLDP_REM_PORT_DESC)
	if err != nil {
		// Port descriptions are optional, just log and continue
		remoteDescs = make(map[string]string)
	}

	// Parse LLDP remote table entries
	// OID format: .1.0.8802.1.1.2.1.4.1.1.X.timeMark.localPortNum.remoteIndex
	for oid, remoteName := range remoteSystems {
		// Extract indices from OID
		parts := strings.Split(oid, ".")
		if len(parts) < 3 {
			continue
		}

		// Last three parts: timeMark, localPortNum, remoteIndex
		timeMark := parts[len(parts)-3]
		localPortNum := parts[len(parts)-2]
		remoteIndex := parts[len(parts)-1]
		indexSuffix := fmt.Sprintf("%s.%s.%s", timeMark, localPortNum, remoteIndex)

		// Get local port name
		localPort := portMap[localPortNum]
		if localPort == "" {
			localPort = fmt.Sprintf("Port%s", localPortNum)
		}

		// Get port speed
		portSpeed := speedMap[localPortNum]

		// Get remote port ID
		remotePortOID := fmt.Sprintf("%s.%s", LLDP_REM_PORT_ID, indexSuffix)
		remotePort := remotePorts[remotePortOID]

		// Get remote description
		remoteDescOID := fmt.Sprintf("%s.%s", LLDP_REM_PORT_DESC, indexSuffix)
		remoteDesc := remoteDescs[remoteDescOID]

		neighbor := LLDPNeighbor{
			LocalDevice:       deviceName,
			LocalPort:         localPort,
			LocalPortSpeed:    portSpeed,
			RemoteDevice:      strings.TrimSpace(remoteName),
			RemotePort:        strings.TrimSpace(remotePort),
			RemoteDescription: strings.TrimSpace(remoteDesc),
		}

		neighbors = append(neighbors, neighbor)
	}

	return neighbors, nil
}

func getInterfaceSpeeds(snmp *gosnmp.GoSNMP) map[string]string {
	speedMap := make(map[string]string)

	// Try ifHighSpeed first (returns speed in Mbps, more accurate for high-speed interfaces)
	highSpeeds, err := snmpWalk(snmp, IF_HIGH_SPEED)
	if err == nil && len(highSpeeds) > 0 {
		for oid, speedStr := range highSpeeds {
			parts := strings.Split(oid, ".")
			portNum := parts[len(parts)-1]

			// ifHighSpeed is in Mbps, convert to human-readable format
			speedMbps := 0
			fmt.Sscanf(speedStr, "%d", &speedMbps)

			if speedMbps == 0 {
				continue // Skip interfaces with 0 speed
			} else if speedMbps >= 1000 {
				// Convert to Gbps
				speedGbps := float64(speedMbps) / 1000.0
				speedMap[portNum] = fmt.Sprintf("%.1fG", speedGbps)
			} else {
				speedMap[portNum] = fmt.Sprintf("%dM", speedMbps)
			}
		}
		return speedMap
	}

	// Fallback to ifSpeed (returns speed in bits/sec, less accurate for >4Gbps)
	speeds, err := snmpWalk(snmp, IF_SPEED)
	if err == nil && len(speeds) > 0 {
		for oid, speedStr := range speeds {
			parts := strings.Split(oid, ".")
			portNum := parts[len(parts)-1]

			// ifSpeed is in bits/sec
			speedBps := uint64(0)
			fmt.Sscanf(speedStr, "%d", &speedBps)

			if speedBps == 0 {
				continue
			}

			// Convert to human-readable format
			speedMbps := speedBps / 1000000
			if speedMbps >= 1000 {
				speedGbps := float64(speedMbps) / 1000.0
				speedMap[portNum] = fmt.Sprintf("%.1fG", speedGbps)
			} else if speedMbps > 0 {
				speedMap[portNum] = fmt.Sprintf("%dM", speedMbps)
			} else {
				speedKbps := speedBps / 1000
				speedMap[portNum] = fmt.Sprintf("%dK", speedKbps)
			}
		}
	}

	return speedMap
}

func getLocalPortMap(snmp *gosnmp.GoSNMP) (map[string]string, error) {
	portMap := make(map[string]string)

	// Try lldpLocPortDesc first
	lldpPorts, err := snmpWalk(snmp, LLDP_LOC_PORT_DESC)
	if err == nil && len(lldpPorts) > 0 {
		for oid, desc := range lldpPorts {
			parts := strings.Split(oid, ".")
			portNum := parts[len(parts)-1]
			portMap[portNum] = strings.TrimSpace(desc)
		}
		return portMap, nil
	}

	// Try ifName
	ifNames, err := snmpWalk(snmp, IF_NAME)
	if err == nil && len(ifNames) > 0 {
		for oid, name := range ifNames {
			parts := strings.Split(oid, ".")
			portNum := parts[len(parts)-1]
			portMap[portNum] = strings.TrimSpace(name)
		}
		return portMap, nil
	}

	// Last resort: ifDescr
	ifDescrs, err := snmpWalk(snmp, IF_DESCR)
	if err == nil && len(ifDescrs) > 0 {
		for oid, desc := range ifDescrs {
			parts := strings.Split(oid, ".")
			portNum := parts[len(parts)-1]
			portMap[portNum] = strings.TrimSpace(desc)
		}
		return portMap, nil
	}

	return portMap, fmt.Errorf("no interface information available")
}

func snmpWalk(snmp *gosnmp.GoSNMP, oid string) (map[string]string, error) {
	results := make(map[string]string)

	err := snmp.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
		oidStr := pdu.Name

		// Convert value to string based on type
		var valueStr string
		switch pdu.Type {
		case gosnmp.OctetString:
			valueStr = string(pdu.Value.([]byte))
		case gosnmp.Integer:
			valueStr = fmt.Sprintf("%d", pdu.Value)
		case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks:
			valueStr = fmt.Sprintf("%d", pdu.Value)
		case gosnmp.IPAddress:
			valueStr = fmt.Sprintf("%s", pdu.Value)
		default:
			valueStr = fmt.Sprintf("%v", pdu.Value)
		}

		results[oidStr] = valueStr
		return nil
	})

	if err != nil {
		return nil, err
	}

	return results, nil
}
