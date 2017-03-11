////#####################////
//    THE CENTRAL CORE!    //
//   AUTHOR - hashcode55   //
////#####################////

package main 
import (
	"log"
	"./packethelper"
	"./protocols"	
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

`, 				msg.Name, msg.FromIP, msg.FromPortNum, 
   				msg.ToIP, msg.ToPortNum, msg.Description)
		default:			
		}
	}
}

func main () {
	packetSource, err := packethelper.GetPackets("tcp")
	if err != nil {
		log.Fatal(err)
	}

	// Channel storing the protocols 
	detectedProtocols := make(chan protocols.Protocol) 

	// Launch a goroutine for pretty printing the details 
	go prettyPrint(detectedProtocols)

	for packet := range packetSource.Packets() {
     	protocols.DetectHTTP(packet, detectedProtocols)     	
     	protocols.DetectSSH(packet, detectedProtocols)
	}	
}