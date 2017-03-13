package main

import (
	"github.com/HashCode55/gopipi"
)

func main() {
	gopipi.PacketCapture("tcp", "en0")
}
