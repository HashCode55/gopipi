////#####################////
//       SSH PROTOCOL      //
//   AUTHOR - hashcode55   //
////#####################////

package protocols

import (
	// "fmt"
	"log"
	"strings"

	"github.com/google/gopacket"
)

func DetectSSH(packet gopacket.Packet, detectedProt chan Protocol) {
	/*
		detecting the ssh protocol
	*/

	p := Protocol{}
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// Search for a string inside the payload
		ssh := string(applicationLayer.Payload())
		if len(ssh) > 7 && len(ssh) < 256 && strings.Contains(ssh, "SSH-") {

			// get the IP/Port details
			p.FromIP, p.ToIP = GetIPAddresses(packet)
			p.FromPortNum, p.ToPortNum = GetPortAddresses(packet)

			p.Name = "SSH"
			p.Description = "No description provided."
			detectedProt <- p
			//fmt.Printf("%s\n", applicationLayer.Payload())
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Fatal("Error decoding some part of the packet:", err)
	}
}
