package nfso80

import (
	"context"
	"errors"
	"net"
	"time"

	"sync/atomic"

	"golang.org/x/net/proxy"
)

// List of errors can be returned by module functions.
var (
	ErrServerClosed = errors.New("nfso80: Server closed")
)

// Time interval to check for all connections to server to be closed
// before finally shutting down.
const shutdownCheckInterval = 2 * time.Second

// Represents the data structure that is instantiated
// to implement NFSO80 server.
type Server struct {
	// Defines interface for the handler will be applied to server.
	Handler interface {
		Serve(conn net.Conn, dialer proxy.ContextDialer)
	}
	// Contains dialer of the x/net library that allows to communicate
	// with the proxy endpoint.
	Dialer proxy.ContextDialer
	// Contains a boolean flag that indicates whether the server should
	// be shutdown or not.
	inShutdown atomic.Bool
	// Contains the net library listener that must contain a TCP socket
	// to accept a connections.
	listener net.Listener
	// Contains a number of connection that have not yet closed.
	counter atomic.Int32
}

func (s *Server) Serve(listener net.Listener) error {
	// We should contain listener in the structure to be able
	// to call shutdown from other goroutines.
	s.listener = listener

	for {
		// We need to increment the counter before accepting to avoid
		// the race condition with shutdown.
		s.counter.Add(1)
		conn, err := listener.Accept()
		if err != nil {
			// It's an error, but counter should be decremented to avoid
			// deadlock.
			s.counter.Add(-1)
			// In case of the shutdown, we need to return an appropriate error.
			if s.inShutdown.Load() {
				return ErrServerClosed
			}
			return err
		}
		// Run the goroutine handler and decrement the counter upon completion.
		go func() {
			s.Handler.Serve(conn, s.Dialer)
			s.counter.Add(-1)
		}()
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	// Mark server as shutting down, so next accept will cause server
	// to be closed.
	s.inShutdown.Store(true)
	// Close the listener to stop accepting new connections.
	if err := s.listener.Close(); err != nil {
		return err
	}
	// Wait for all connections to complete before returning control.
	timer := time.NewTimer(shutdownCheckInterval)
	for {
		if s.counter.Load() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(shutdownCheckInterval)
		}
	}
}

// vim: set ts=4 sw=4 noexpandtab:
