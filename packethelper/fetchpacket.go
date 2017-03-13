package packethelper

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device       string
	snapshot_len int32 = 65535
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
)

func FindDevices() {
	/*
		Helper function to print the list of
		network adaptors in your machine.
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

func GetPackets(filter, _device string) (*gopacket.PacketSource, error) {
	/*
		Return the packet source for further inspection
	*/
	device = _device // set the device

	handle, err := pcap.OpenLive(
		device,
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
