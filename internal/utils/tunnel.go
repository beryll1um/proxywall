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

func (t Tunnel) Establish() error {
	// Copies from proxy to client connection and vice versa
	// until one of them closes it.
	finish := make(chan error)

	go func() {
		_, err := io.Copy(t.Conn1, t.Conn2)
		finish <- err
	}()
	go func() {
		_, err := io.Copy(t.Conn2, t.Conn1)
		finish <- err
	}()

	// The first one should be nil (EOF under the hood),
	// otherwise something unexpected happened.
	if err := <-finish; err != nil {
		return err
	}

	// We need to wait for the second goroutine to complete,
	// otherwise a leak will occur.
	<-finish

	return nil
}

// vim: set ts=4 sw=4 noexpandtab:
