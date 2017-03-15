////#####################////
//      HTTP PROTOCOL      //
//   AUTHOR - hashcode55   //
////#####################////

package protocols

import (
	"github.com/google/gopacket"
	"log"
	"strings"
)

// request types
var requestTypes = [...]string{"GET ", "POST ", "OPTIONS ", "HEAD ", "PUT ",
	"DELETE ", "CONNECT ", "PROPFIND ", "REPORT "}

func httpRequest(payload string) int {
	/*
		Checks if the HTTP payload contains a request or not.
		Refer https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/http.c#L470
	*/
	for index, rt := range requestTypes {
		if strings.HasPrefix(payload, rt) {
			return index
		}
	}
	// not a request
	return -1
}

// TODO Sequence number for packet health based on the discussion with my professor
func DetectHTTP(packet gopacket.Packet, detectedProt chan Protocol) {
	/*
		detecting the http protocol
	*/
	p := Protocol{}

	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {

		p.FromIP, p.ToIP = GetIPAddresses(packet)
		p.FromPortNum, p.ToPortNum = GetPortAddresses(packet)

		payload := string(applicationLayer.Payload())

		// check if its an HTTP request
		request := httpRequest(payload)

		if request != -1 {
			p.Name = "HTTP"
			p.Description = "Packet contains HTTP " + requestTypes[request] + "request.\n"
			detectedProt <- p
		} else if strings.HasPrefix(payload, "HTTP/1.") {
			p.Name = "HTTP"
			p.Description = "Packet contains HTTP response."
			detectedProt <- p
		}
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		log.Fatal("Error decoding some part of the packet:", err)
	}
}
