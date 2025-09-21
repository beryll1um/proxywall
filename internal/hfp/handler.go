package hfp

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	u "github.com/beryll1um/proxywall/internal/utils"
)

// List of errors can be returned by module functions.
var (
	ErrProxyAuth = errors.New("hfp: Failed to authenticate with proxy server")
)

func httpTunnelAuth(conn net.Conn, url string, cred []byte) error {
	// First we need to send the corresponding authentication request.
	if _, err := fmt.Fprintf(conn,
		"CONNECT %s HTTP/1.1\r\n" +
		"Proxy-Authorization: Basic %s\r\n" +
		"Host: %s\r\n\r\n",
		url, base64.StdEncoding.EncodeToString(cred), url,
	); err != nil {
		return errors.New("failed to send HTTP request")
	}

	// Wait for the sucessfull response or return error.
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return errors.New("failed to receive HTTP response")
	}
	// If the status code isn't OK, we need to return a proxy auth error.
	if resp.StatusCode != http.StatusOK {
		return ErrProxyAuth
	}

	return nil
}

// Represents the data structure that is instantiated
// to implement Server Handler interface.
type Handler struct {
	// Helps lighten a shady areas of this mysterious behavior a bit.
	Logger *logrus.Entry
	// Counts the number of hijacked connections and waits for them.
	wg sync.WaitGroup
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	// The username is required because it contains the source address.
	creds := strings.Split(req.Header.Get("Proxy-Authorization"), " ")
	if len(creds) != 2 || creds[0] != "Basic" {
		writer.Header().Set("Proxy-Authenticate", "Basic realm=\"TargetHFP\"")
		http.Error(writer, "Unauthorized connections is not allowed",
			http.StatusProxyAuthRequired)
		return
	}

	// Decode Bearer token and search for the destination address end.
	auth, err := base64.StdEncoding.DecodeString(creds[1])
	delidx := strings.LastIndexByte(string(auth), '@')
	if err != nil || delidx == -1 {
		http.Error(writer, "Wrong format of the Basic authentication token",
			http.StatusUnauthorized)
		return
	}

	// Next we need to dial other end and establish connectivity.
	dstHost := string(auth[delidx + 1:])
	dstConn, err := net.Dial("tcp", dstHost)
	if err != nil {
		http.Error(writer, "Failed to dial target destination",
			http.StatusBadGateway)
		return
	}
	defer dstConn.Close()

	// Authenticate with HTTP proxy tunnel using CONNECT method protocol.
	if err := httpTunnelAuth(dstConn, req.Host, auth[:delidx]); err != nil {
		switch err {
		case ErrProxyAuth:
			http.Error(writer, "Failed to authenticate with proxy server",
				http.StatusUnauthorized)
		default:
			http.Error(writer, "Failed to communicate with proxy server",
				http.StatusBadGateway)
		}
		return
	}

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

	// Now we can hijack source connection from HTTP engine.
	srcConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(writer, "Failed to hijack internal HTTP connection",
			http.StatusInternalServerError)
		return
	}
	defer srcConn.Close()

	// We need to create a logger here as it will be used in both cases.
	log := h.Logger.WithFields(logrus.Fields{
		"to": req.Host,
		"via": dstHost,
		// I don't think there can be an unknown remote address here.
		"from": srcConn.RemoteAddr().String(),
	})

	if req.Method == http.MethodConnect {
		// According to the protocol we need to send 200 OK back.
		fmt.Fprintf(srcConn, "HTTP/%d.%d 200 OK\r\n\r\n", req.ProtoMajor,
			req.ProtoMinor)

		log.Trace("redirection tunnel is established")
		// Create a tunnel between these two connections and wait for it to close.
		u.Tunnel{Conn1: dstConn, Conn2: srcConn}.Establish()
		// It's useful to see when connection is done.
		log.Trace("redirection tunnel is closed")
	} else {
		// Since we already hijacked connection, we can reuse the request.
		req.Header.Set("Proxy-Authorization", "Basic " +
			base64.StdEncoding.EncodeToString(auth[:delidx]))

		// Send this HTTP request to the destination connection.
		if err := req.Write(dstConn); err != nil {
			log.Error("failed to send HTTP request to proxy endpoint")
			return
		}
		log.Trace("HTTP request is forwarded to proxy endpoint")

		// Wait for the successful response or log error.
		resp, err := http.ReadResponse(bufio.NewReader(dstConn), req)
		if err != nil {
			log.Error("failed to receive HTTP response from proxy endpoint")
			return
		}
		log.Trace("HTTP response was received from proxy endpoint")

		// Keep-alive support is not currently implemented,
		// close must be responded.
		resp.Header.Set("Connection", "close")
		// Forward response to the originator (source of the proxy connection).
		if err := resp.Write(srcConn); err != nil {
			log.Error("failed to forward HTTP response to originator")
			return
		}
		log.Trace("HTTP response is forwarded to originator")
	}
}

func (h *Handler) Wait() {
	// I don't want to expose all of the WG methods to the handler.
	h.wg.Wait()
}

// vim: set ts=4 sw=4 noexpandtab:
