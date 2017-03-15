////#####################////
//    THE CENTRAL CORE!    //
//   AUTHOR - hashcode55   //
////#####################////

package gopipi

import (
	"github.com/HashCode55/go-PIPI/packethelper"
	"github.com/HashCode55/go-PIPI/protocols"
	"log"
)

func prettyPrint(detectProt chan protocols.Protocol) {
	/*
		Prints the details of detected protocols
	*/
	for {
		// wait for the channel to pop any protocol
		select {
		case msg := <-detectProt:
			log.Printf(`%s protocol found. Packet details -
From IP Adress   : %s
From Port Number : %s
To IP Address    : %s
To Port Number   : %s
Description      : %s

`, msg.Name, msg.FromIP, msg.FromPortNum,
				msg.ToIP, msg.ToPortNum, msg.Description)
		default:
		}
	}
}

func PacketCapture(filter, device string) {
	/*
		This is the root function which captures the packets and forwards it.
	*/
	packetSource, err := packethelper.GetPackets(filter, device)
	if err != nil {
		log.Fatal(err)
	}

	// Channel storing the protocols
	detectedProtocols := make(chan protocols.Protocol)

	// Launch a goroutine for pretty printing the details
	go prettyPrint(detectedProtocols)

	for packet := range packetSource.Packets() {
		protocols.Detect(packet, detectedProtocols)
	}
}
