////#####################////
//      HTTP PROTOCOL      //
//   AUTHOR - hashcode55   //
////#####################////

package protocols

import (
	"log"
	"strings"

	"github.com/google/gopacket"
)

func DetectHTTP(packet gopacket.Packet, detectedProt chan Protocol) {
	/*
		detecting the http protocol
	*/
	p := Protocol{}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// Search for a string inside the payload
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {

			p.FromIP, p.ToIP = GetIPAddresses(packet)
			p.FromPortNum, p.ToPortNum = GetPortAddresses(packet)
			// put the name and description
			p.Name = "HTTP"
			p.Description = "No description provided."

			// push the protocol into the channel
			detectedProt <- p
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Fatal("Error decoding some part of the packet:", err)
	}
}
