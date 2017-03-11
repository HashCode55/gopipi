package packethelper 

import (
	"time"
	"log"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)


var (
    device       string = "en0" // if on a linux, use eth0
    snapshot_len int32  = 65535
    promiscuous  bool   = false 
    err          error
    timeout      time.Duration = -1 * time.Second
    handle       *pcap.Handle
)

func FindDevices () {
	/*
	Helper function to get the devices list
	*/
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	// Print device information
    fmt.Println("Devices found:")
    for _, device := range devices {
        fmt.Println("\nName: ", device.Name)
        fmt.Println("Description: ", device.Description)
        fmt.Println("Devices addresses: ", device.Description)
        for _, address := range device.Addresses {
            fmt.Println("- IP address: ", address.IP)
            fmt.Println("- Subnet mask: ", address.Netmask)
        }
    }
}

func GetPackets(filter string) (*gopacket.PacketSource, error) {
	/*
	Return the packet source for further inspection
	*/
	handle, err := pcap.OpenLive(
		"en0",
		snapshot_len,
		promiscuous, 
		timeout,		
	)
	if err != nil {
		return nil, err 
	}

    // set the filter to monitor HTTP traffic for now 
	handle.SetBPFFilter(filter) 
	
	packetSource := gopacket.NewPacketSource(
		handle, 
		handle.LinkType(),
	)
	
	return packetSource, nil
}