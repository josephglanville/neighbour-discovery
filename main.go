package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func findInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		// Return the first active, non-loopback interface
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			return iface.Name, nil
		}
	}
	return "", fmt.Errorf("no active network interface found")
}

func handleLLDPPacket(packet gopacket.Packet) {
	lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery)
	if lldpLayer != nil {
		lldp, _ := lldpLayer.(*layers.LinkLayerDiscovery)
		lldpInfo := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo)
		if lldp != nil {
			fmt.Printf("LLDP Packet detected\n")
			fmt.Printf("Chassis ID: %s\n", lldp.ChassisID)
			fmt.Printf("Port ID: %s\n", lldp.PortID)
		}
		if lldpInfo != nil {
			info, _ := lldpInfo.(*layers.LinkLayerDiscoveryInfo)
			fmt.Printf("Port Description %s\n", info.PortDescription)
			fmt.Printf("System Name: %s\n", info.SysName)
			fmt.Printf("System Description: %s\n", info.SysDescription)
		}
	}
}

func handleCDPPacket(packet gopacket.Packet) {
	cdpLayer := packet.Layer(layers.LayerTypeCiscoDiscoveryInfo)
	if cdpLayer != nil {
		cdp, _ := cdpLayer.(*layers.CiscoDiscoveryInfo)
		fmt.Printf("CDP Packet detected\n")
		fmt.Printf("Device ID: %s\n", cdp.DeviceID)
		fmt.Printf("Port ID: %s\n", cdp.PortID)
		fmt.Printf("System Name: %s\n", cdp.SysName)
		fmt.Printf("Platform: %s\n", cdp.Platform)
	}
}

func capturePackets(iface string) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set BPF filter for LLDP (EtherType 0x88cc) and CDP (EtherType 0x2000)
	err = handle.SetBPFFilter("ether proto 0x88cc or ether proto 0x2000")
	if err != nil {
		log.Fatal("Error setting BPF filter:", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			continue
		}

		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		switch ethernetPacket.EthernetType {
		case layers.EthernetTypeLinkLayerDiscovery:
			handleLLDPPacket(packet)
		case layers.EthernetTypeCiscoDiscovery:
			handleCDPPacket(packet)
		default:
			// Unhandled EtherType
			continue
		}
	}
}

func main() {
	iface, err := findInterface()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Listening on interface: %s\n", iface)

	go capturePackets(iface)
	time.Sleep(30 * time.Second)

	fmt.Println("Stopping packet capture.")
}
