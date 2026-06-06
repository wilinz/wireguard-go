package main

// SOCKS5 proxy backed by github.com/things-go/go-socks5. Outbound connections
// are dialed through the WireGuard userspace netstack (tnet), and hostnames are
// resolved inside the tunnel, so traffic never touches any system interface,
// route table or resolver. Authentication is optional: with credentials it
// requires username/password (RFC 1929); without, it accepts the no-auth method.

import (
	"context"
	"net"

	socks5 "github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// netstackResolver resolves hostnames inside the tunnel via the netstack DNS,
// so SOCKS5 requests for internal names work without touching the host resolver.
type netstackResolver struct {
	tnet *netstack.Net
}

func (r netstackResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	// Literal IPs need no DNS lookup. This also covers the 0.0.0.0 placeholder
	// that clients send as the source address in a UDP ASSOCIATE request.
	if ip := net.ParseIP(name); ip != nil {
		return ctx, ip, nil
	}
	// Some clients (e.g. PySocks) send "0" or "" as the UDP ASSOCIATE source
	// placeholder; the Go stdlib resolver maps "0" to 0.0.0.0, so mirror that
	// rather than failing the whole associate setup with "no such host".
	if name == "" || name == "0" {
		return ctx, net.IPv4zero, nil
	}
	addrs, err := r.tnet.LookupHost(name)
	if err != nil {
		return ctx, nil, err
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			return ctx, ip, nil
		}
	}
	return ctx, nil, &net.DNSError{Err: "no addresses found", Name: name}
}

// socksLogger adapts device.Logger to the go-socks5 Logger interface.
type socksLogger struct {
	logger *device.Logger
}

func (l socksLogger) Errorf(format string, args ...interface{}) {
	l.logger.Errorf("socks5: "+format, args...)
}

// startSocks5 binds a SOCKS5 listener on the host and serves it in the
// background. When username is non-empty, username/password authentication is
// required (clients offering only no-auth are rejected).
func startSocks5(listen, username, password string, tnet *netstack.Net, logger *device.Logger) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}

	opts := []socks5.Option{
		socks5.WithResolver(netstackResolver{tnet: tnet}),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, addr)
		}),
		socks5.WithLogger(socksLogger{logger: logger}),
	}
	if username != "" {
		// go-socks5 enables UserPassAuthenticator only (no no-auth fallback)
		// once credentials are set, so unauthenticated clients are rejected.
		opts = append(opts, socks5.WithCredential(socks5.StaticCredentials{
			username: password,
		}))
		logger.Verbosef("socks5: username/password authentication enabled")
	}

	server := socks5.NewServer(opts...)
	go func() {
		if err := server.Serve(ln); err != nil {
			logger.Errorf("socks5: serve stopped: %v", err)
		}
	}()
	return nil
}
