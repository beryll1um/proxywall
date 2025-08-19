package nfso80

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"

	u "github.com/beryll1um/proxywall/internal/utils"
)

// Represents the data structure that is instantiated
// to implement Server Handler interface.
type Handler struct {
	// Helps lighten a shady areas of this mysterious behavior a bit.
	Logger logrus.Entry
	// Contains a pointer to a managed Redis object, which can be either
	// a cluster or a standalone instance.
	Resc redis.Cmdable
	// Either forces RDNS (forces the use of only the domain, the reverse IP),
	// or allows the use of an IP address if domain is not found.
	ForceRDNS bool
}

func (h Handler) Serve(conn net.Conn, dialer proxy.Dialer) {
	// It is extremely important to close the connection after completing
	// the pass-through procedure.
	defer conn.Close()

	// First we need to prove that the connection is real TCP.
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		h.Logger.Error("unable to service unknown connection type")
		return
	}

	h.Logger.Trace("connection accepted")

	// To access the socket file descriptor we need a raw network connection.
	rawConn, err := tcp.SyscallConn()
	if err != nil {
		h.Logger.Error("failed to obtain raw network connection")
		return
	}

	var sa u.RawSockaddrAny
	var syscallErr error

	// This function allows us to access the file handle inside the callback.
	if err := rawConn.Control(func(fd uintptr) {
		// There shouldn't be any problems since we only allow TCP listener.
		if conn.RemoteAddr().(*net.TCPAddr).IP.To4() != nil {
			syscallErr = u.GetOriginalDst4(fd, &sa)
		} else {
			syscallErr = u.GetOriginalDst6(fd, &sa)
		}
	}); err != nil {
		h.Logger.WithError(err).Error("failed to invoke file descriptor")
		return
	}
	if syscallErr != nil {
		h.Logger.WithError(err).Error("failed to get original destination")
		return
	}

	dst := sa.IP().String()
	// If Redis client is specified, we need to search
	// the corresponding domains for IP addresses.
	if h.Resc != nil {
		domain, err := h.Resc.Get(context.TODO(), dst).Result()
		if err != nil {
			h.Logger.Warningf("unable to find '%s' address domain", dst)
			if h.ForceRDNS {
				h.Logger.Error("dropped due to domain unavailability")
				return
			}
		} else {
			dst = domain
		}
	}

	addr := fmt.Sprintf("%s:%d", dst, sa.Port())
	proxyConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		h.Logger.WithError(err).Error("failed to connect proxy")
		return
	}
	defer proxyConn.Close()

	log := h.Logger.WithField("to", addr)
	log.Trace("redirection tunnel is established")

	// Copies from proxy to client connection and vice versa
	// until one of them closes it.
	finish := make(chan error)

	go func() {
		_, err := io.Copy(proxyConn, conn)
		finish <- err
	}()
	go func() {
		_, err := io.Copy(conn, proxyConn)
		finish <- err
	}()

	// The first one should be nil (EOF under the hood),
	// otherwise something unexpected happened.
	if err := <-finish; err != nil {
		log.WithError(err).Error("connection lost due to error")
	}

	// The second one should be finished with error
	// as it's destination is died.
	<-finish

	log.Trace("redirection tunnel is closed")
}

// vim: set ts=4 sw=4 noexpandtab:
