package rpc

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

// Config provides configuration parameters of the rpc server.
type Config struct {
	DisableTLS bool
	Key        string
	Cert       string
	User       string
	Pass       string
	LimitUser  string
	LimitPass  string
	MaxClients uint32
	Listeners  []string
}

func (cfg *Config) String() string {
	var tls string
	if cfg.DisableTLS {
		tls = "false"
	} else {
		tls = "true"
	}
	
	return fmt.Sprintf("{tls:%s, user:%s, pass:%s, listeners:%v}", tls, cfg.User, cfg.Pass, cfg.Listeners)
}

// FileExists reports whether the named file or directory exists.
func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// ParseListeners splits the list of listen addresses passed in addrs into
// IPv4 and IPv6 slices and returns them. This allows easy creation of the
// listeners on the correct interface "tcp4" and "tcp6". It also properly
// detects addresses which apply to "all interfaces" and adds the address to
// both slices.
func ParseListeners(addrs []string) ([]string, []string, error) {
	ipv4ListenAddrs := make([]string, 0, len(addrs)*2)
	ipv6ListenAddrs := make([]string, 0, len(addrs)*2)

	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// Shouldn't happen due to already being normalized.
			return nil, nil, err
		}

		// Empty host or host of * on plan9 is both IPv4 and IPv6.
		if host == "" || (host == "*" && runtime.GOOS == "plan9") {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
			continue
		}

		// Parse the IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, nil, fmt.Errorf("'%s' is not a "+
				"valid IP address", host)
		}

		// To4 returns nil when the IP is not an IPv4 address, so use
		// this determine the address type.
		if ip.To4() == nil {
			ipv6ListenAddrs = append(ipv6ListenAddrs, addr)
		} else {
			ipv4ListenAddrs = append(ipv4ListenAddrs, addr)
		}
	}
	return ipv4ListenAddrs, ipv6ListenAddrs, nil
}
