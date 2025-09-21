package nfso80

import (
	"context"
	"errors"
	"net"
	"sync/atomic"

	"golang.org/x/net/proxy"

	u "github.com/beryll1um/proxywall/internal/utils"
)

type Dialer struct {
	// Dialers to be used in RR cycle.
	children []proxy.ContextDialer
	// Incremental counter that decides which dialer to use.
	counter atomic.Int64
}

func NewDialer(endpoints []string) (*Dialer, error) {
	dialer := &Dialer{}
	dialer.counter.Store(-1)
	for _, endpoint := range endpoints {
		// Only SOCKS5 proxy endpoints is currently supported.
		url, err := u.UrlBuilder{Scheme: "socks5"}.String(endpoint)
		if err != nil {
			return nil, errors.Join(
				errors.New("failed to configure SOCKS5 dialer"), err)
		}
		childDialer, err := proxy.FromURL(url, proxy.Direct)
		if err != nil {
			return nil, errors.Join(
				errors.New("failed to setup SOCKS5 dialer"), err)
		}
		childCtxDialer, ok := childDialer.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("failed to setup SOCKS5 context dialer")
		}
		dialer.children = append(dialer.children, childCtxDialer)
	}
	return dialer, nil
}

func (d *Dialer) DialContext(
	ctx context.Context, network, addr string,
) (net.Conn, error) {
	// Select next dialer in the RR cycle.
	childCtxDialer := d.children[d.counter.Add(1) % int64(len(d.children))]
	return childCtxDialer.DialContext(ctx, network, addr)
}

// vim: set ts=4 sw=4 noexpandtab:
