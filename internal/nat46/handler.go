package nat46

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	u "github.com/beryll1um/proxywall/internal/utils"
)

// Represents the data structure that is instantiated
// to implement Server Handler interface.
type Handler struct {
	// Helps lighten a shady areas of this mysterious behavior a bit.
	Logger *logrus.Entry
	// Counts the number of hijacked connections and waits for them.
	wg sync.WaitGroup
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	// We can only accept HTTP CONNECT method since this is an HTTP tunnel.
	if req.Method != http.MethodConnect {
		writer.Header().Set("Allow", http.MethodConnect)
		http.Error(writer, "Method is not allowed for NAT46 server",
			http.StatusMethodNotAllowed)
		return
	}

	// The username is required because it contains the source address.
	creds := strings.Split(req.Header.Get("Proxy-Authorization"), " ")
	if len(creds) != 2 || creds[0] != "Basic" {
		writer.Header().Set("Proxy-Authenticate", "Basic realm=\"SrcIPv6\"")
		http.Error(writer, "Unauthorized connections is not allowed",
			http.StatusProxyAuthRequired)
		return
	}

	// Decode Bearer token and search for the username end.
	userpass, err := base64.StdEncoding.DecodeString(creds[1])
	delidx := strings.LastIndexByte(string(userpass), ':')
	if err != nil || delidx == -1 {
		http.Error(writer, "Wrong format of the Basic authentication token",
			http.StatusUnauthorized)
		return
	}

	// We also need to resolve this address and prove its validity.
	localAddr, err := net.ResolveTCPAddr("tcp6", string(userpass[:delidx]))
	if err != nil {
		http.Error(writer, "Username should be an IPv6 source address",
			http.StatusUnauthorized)
		return
	}

	// Next we need to dial other end and establish connectivity.
	dstConn, err := (&net.Dialer{LocalAddr: localAddr}).Dial("tcp", req.Host)
	if err != nil {
		http.Error(writer, "Failed to dial target hostname",
			http.StatusBadGateway)
		return
	}
	defer dstConn.Close()

	// Now we need to try to cast writer to hijacker. It may not work!
	hj, ok := writer.(http.Hijacker)
	if !ok {
		http.Error(writer, "Hijacking is not possible on current server",
			http.StatusInternalServerError)
		return
	}

	// Increase the wait group to wait for all intercepted connections
	// to complete before terminating execution.
	h.wg.Add(1)
	defer h.wg.Done()

	// Finally, we can hijack source connection from HTTP engine.
	srcConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(writer, "Failed to hijack internal HTTP connection",
			http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	// According to the protocol we need to send 200 OK back.
	fmt.Fprintf(srcConn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor,
		req.ProtoMinor)

	log := h.Logger.WithFields(logrus.Fields{
		"to": req.Host, "from": localAddr.String(),
	})
	log.Trace("redirection tunnel is established")

	// Create a tunnel between these two connections and wait for it to close.
	if err := (u.Tunnel{
		Conn1: dstConn,
		Conn2: srcConn,
	}).Establish(); err != nil {
		log.WithError(err).Error("connection lost due to error")
	}

	// It's useful to see when connection is done.
	log.Trace("redirection tunnel is closed")
}

func (h *Handler) Wait() {
	// I don't want to expose all of the WG methods to the handler.
	h.wg.Wait()
}

// vim: set ts=4 sw=4 noexpandtab:
