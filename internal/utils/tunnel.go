package utils

import (
	"io"
	"net"
)

// Represents the data structure that is instantiated
// to implement connections Tunnel.
type Tunnel struct {
	// First peer of the tunnel (both of them are mirrored).
	Conn1 net.Conn
	// Second peer of the tunnel (both of them are mirrored).
	Conn2 net.Conn
}

func (t Tunnel) Establish() {
	// We need to somehow communicate with the original goroutine.
	finish := make(chan struct{}, 2)

	go func() {
		io.Copy(t.Conn1, t.Conn2)
		finish <- struct{}{}
	}()
	go func() {
		io.Copy(t.Conn2, t.Conn1)
		finish <- struct{}{}
	}()

	// Wait for at least one goroutine to finish.
	<-finish
	// We don't actually know which connection caused the connection to close,
	// so to avoid playing with errors, let's just try to close both.
	t.Conn1.Close()
	t.Conn2.Close()
}

// vim: set ts=4 sw=4 noexpandtab:
