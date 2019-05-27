package main

import (
	"log"

	"github.com/lann/tuya/device"
	"github.com/lann/tuya/net"
)

func main() {
	l, err := net.NewStatusListener()
	if err != nil {
		log.Fatalf("NewStatusListener failed: %v", err)
	}
	defer l.Close()

	for {
		status, err := l.ReadStatus()
		fatalErr(err, "ReadStatus failed")

		log.Printf("Device: %#v", status)

		config := status.ClientConfig()
		config.Key = "f4f603d680c9d23d"
		client, err := config.Dial()
		fatalErr(err, "Dial failed")

		man := device.NewManager(status.GatewayID, client)

		state, err := man.GetState()
		fatalErr(err, "GetState failed")

		log.Printf("State: %v", state)

		//state[1] = !state[1].(bool)
		//err = man.SetState(state)
		//fatalErr(err, "SetState failed")

		man.Close()
	}
}

func fatalErr(err error, prefix string) {
	if err != nil {
		if prefix != "" {
			prefix += ": "
		}
		log.Fatalf("%s%v", prefix, err)
	}
}
