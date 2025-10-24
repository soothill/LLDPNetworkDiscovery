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

		// Get remote port ID
		remotePortOID := fmt.Sprintf("%s.%s", LLDP_REM_PORT_ID, indexSuffix)
		remotePort := remotePorts[remotePortOID]

		// Get remote description
		remoteDescOID := fmt.Sprintf("%s.%s", LLDP_REM_PORT_DESC, indexSuffix)
		remoteDesc := remoteDescs[remoteDescOID]

		neighbor := LLDPNeighbor{
			LocalDevice:       deviceName,
			LocalPort:         localPort,
			RemoteDevice:      strings.TrimSpace(remoteName),
			RemotePort:        strings.TrimSpace(remotePort),
			RemoteDescription: strings.TrimSpace(remoteDesc),
		}

		neighbors = append(neighbors, neighbor)
	}

	return neighbors, nil
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
