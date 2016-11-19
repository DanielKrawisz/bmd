// Originally derived from: btcsuite/btcd/config.go
// Copyright (c) 2013-2015 The btcsuite developers

// Copyright (c) 2015 Monetas.
// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DanielKrawisz/bmd/database"
	_ "github.com/DanielKrawisz/bmd/database/bdb"
	_ "github.com/DanielKrawisz/bmd/database/memdb"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/go-socks/socks"
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultConfigFilename  = "bmd.conf"
	defaultLogLevel        = "info"
	defaultLogDirname      = "logs"
	defaultLogFilename     = "bmd.log"
	defaultMaxPeers        = 125
	defaultBanDuration     = time.Hour * 24
	defaultMaxRPCClients   = 25
	defaultDbType          = "boltdb"
	defaultPort            = 8444
	defaultRPCPort         = 8442
	defaultMaxUpPerPeer    = 2 * 1024 * 1024 // 2MBps
	defaultMaxDownPerPeer  = 2 * 1024 * 1024 // 2MBps
	defaultMaxOutbound     = 10
	defaultRequestTimeout  = time.Minute * 3
	defaultCleanupInterval = time.Hour
)

var (
	defaultDataDir     = btcutil.AppDataDir("bmd", false)
	defaultConfigFile  = filepath.Join(defaultDataDir, defaultConfigFilename)
	knownDbTypes       = database.SupportedDBs()
	defaultRPCKeyFile  = filepath.Join(defaultDataDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(defaultDataDir, "rpc.cert")
	defaultLogDir      = filepath.Join(defaultDataDir, defaultLogDirname)

	defaultDNSSeeds = []string{
		"bootstrap8444.bitmessage.org:8444",
		"bootstrap8080.bitmessage.org:8080"}

	defaultInitialNodes = []string{
		"bitmessage.stashcrypto.net:8444",
		"iifpqv7hwcdjspbb.onion:8444",
		"5.45.99.75:8444",
		"75.167.159.54:8444",
		"95.165.168.168:8444",
		"85.180.139.241:8444",
		"158.222.211.81:8080",
		"178.62.12.187:8448",
		"24.188.198.204:8111",
		"109.147.204.113:1195",
		"178.11.46.221:8444"}
)

// Filesize is a custom configuration option for go-flags. It is used to parse
// common filesize appendages like B, K, M, G which mean bytes, kilobytes,
// megabytes and gigabytes respectively. It stores sizes internally in the form
// of bytes (int64).
type Filesize int64

// MarshalFlag returns a file size as a string.
func (size Filesize) MarshalFlag() (string, error) {
	s := int64(size)
	if s < 1024 { // B
		return fmt.Sprintf("%dB", s), nil
	} else if s < 1024*1024 { // KB
		return fmt.Sprintf("%.2fK", float64(size)/1024), nil
	} else if s < 1024*1024*1024 { // MB
		return fmt.Sprintf("%.2fM", float64(size)/(1024*1024)), nil
	} // GB
	return fmt.Sprintf("%.2fG", float64(size)/(1024*1024*1024)), nil
}

// UnmarshalFlag takes a string and interprets it as a Filesize.
func (size *Filesize) UnmarshalFlag(value string) error {
	if len(value) < 2 {
		return errors.New("invalid input")
	}
	unit := strings.ToUpper(value[len(value)-1:]) // last letter
	v := value[:len(value)-1]                     // till last letter

	s, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return err
	}

	switch unit {
	case "B": // leave as it is
	case "K":
		s *= 1024
	case "M":
		s *= 1024 * 1024
	case "G":
		s *= 1024 * 1024 * 1024
	default:
		return errors.New("unknown unit")
	}

	*size = Filesize(int64(s))
	return nil
}

// config defines the configuration options for bmd.
//
// See loadConfig for details on the configuration load process.
type config struct {
	ShowVersion     bool          `short:"V" long:"version" description:"Display version information and exit"`
	ConfigFile      string        `short:"C" long:"configfile" description:"Path to configuration file"`
	DataDir         string        `short:"b" long:"datadir" description:"Directory to store data"`
	LogDir          string        `long:"logdir" description:"Directory to log output"`
	AddPeers        []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	ConnectPeers    []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	DisableListen   bool          `long:"nolisten" description:"Disable listening for incoming connections -- NOTE: Listening is automatically disabled if the --connect or --proxy options are used without also specifying listen interfaces via --listen"`
	Listeners       []string      `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 8444)"`
	MaxPeers        int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	RPCUser         string        `short:"u" long:"rpcuser" description:"Username for RPC connections"`
	RPCPass         string        `short:"P" long:"rpcpass" default-mask:"-" description:"Password for RPC connections"`
	RPCLimitUser    string        `long:"rpclimituser" description:"Username for limited RPC connections"`
	RPCLimitPass    string        `long:"rpclimitpass" default-mask:"-" description:"Password for limited RPC connections"`
	RPCListeners    []string      `long:"rpclisten" description:"Add an interface/port to listen for RPC connections (default port: 8442)"`
	RPCCert         string        `long:"rpccert" description:"File containing the certificate file"`
	RPCKey          string        `long:"rpckey" description:"File containing the certificate key"`
	RPCMaxClients   int           `long:"rpcmaxclients" description:"Max number of RPC clients"`
	DisableRPC      bool          `long:"norpc" description:"Disable built-in RPC server -- NOTE: The RPC server is disabled by default if no rpcuser/rpcpass or rpclimituser/rpclimitpass is specified"`
	DisableTLS      bool          `long:"notls" description:"Disable TLS for the RPC server -- NOTE: This is only allowed if the RPC server is bound to localhost"`
	DisableDNSSeed  bool          `long:"nodnsseed" description:"Disable DNS seeding for peers"`
	ExternalIPs     []string      `long:"externalip" description:"Add an ip to the list of local addresses we claim to listen on to peers"`
	Proxy           string        `long:"proxy" description:"Connect via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	ProxyUser       string        `long:"proxyuser" description:"Username for proxy server"`
	ProxyPass       string        `long:"proxypass" default-mask:"-" description:"Password for proxy server"`
	OnionProxy      string        `long:"onion" description:"Connect to tor hidden services via SOCKS5 proxy (eg. 127.0.0.1:9050)"`
	OnionProxyUser  string        `long:"onionuser" description:"Username for onion proxy server"`
	OnionProxyPass  string        `long:"onionpass" default-mask:"-" description:"Password for onion proxy server"`
	NoOnion         bool          `long:"noonion" description:"Disable connecting to tor hidden services"`
	TorIsolation    bool          `long:"torisolation" description:"Enable Tor stream isolation by randomizing user credentials for each connection."`
	DbType          string        `long:"dbtype" description:"Database backend to use. Options: {memdb (for testing), boltdb}"`
	Profile         string        `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`
	CPUProfile      string        `long:"cpuprofile" description:"Write CPU profile to the specified file"`
	DebugLevel      string        `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`
	Upnp            bool          `long:"upnp" description:"Use UPnP to map our listening port outside of NAT"`
	MaxUpPerPeer    Filesize      `long:"maxupload" description:"Maximum upload rate for any peer. Valid units are {B, K, M, G} bytes/sec"`
	MaxDownPerPeer  Filesize      `long:"maxdownload" description:"Maximum download rate for any peer. Valid units are {B, K, M, G} bytes/sec"`
	MaxOutbound     int           `long:"maxoutbound" description:"The maximum number of outbound peers that bmd will try to maintain"`
	RequestExpire   time.Duration `long:"requestexpire" description:"Duration after which an object request to a peer must expire. Valid time units are {s, m, h}. Minimum 10 seconds"`
	CleanupInterval time.Duration `long:"cleanupinterval" description:"Time interval after which expired objects are removed. Valid time units are {s, m, h}. Minimum 20 minutes"`
	onionlookup     func(string) ([]net.IP, error)
	lookup          func(string) ([]net.IP, error)
	oniondial       func(string, string) (net.Conn, error)
	dial            func(string, string) (net.Conn, error)
	dnsSeeds        []string
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(defaultDataDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but they variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// validLogLevel returns whether or not logLevel is a valid debug log level.
func validLogLevel(logLevel string) bool {
	switch logLevel {
	case "trace":
		fallthrough
	case "debug":
		fallthrough
	case "info":
		fallthrough
	case "warn":
		fallthrough
	case "error":
		fallthrough
	case "critical":
		return true
	}
	return false
}

// supportedSubsystems returns a sorted slice of the supported subsystems for
// logging purposes.
func supportedSubsystems() []string {
	// Convert the subsystemLoggers map keys to a slice.
	subsystems := make([]string, 0, len(subsystemLoggers))
	for subsysID := range subsystemLoggers {
		subsystems = append(subsystems, subsysID)
	}

	// Sort the subsytems for stable display.
	sort.Strings(subsystems)
	return subsystems
}

// parseAndSetDebugLevels attempts to parse the specified debug level and set
// the levels accordingly.  An appropriate error is returned if anything is
// invalid.
func parseAndSetDebugLevels(debugLevel string) error {
	// When the specified string doesn't have any delimters, treat it as
	// the log level for all subsystems.
	if !strings.Contains(debugLevel, ",") && !strings.Contains(debugLevel, "=") {
		// Validate debug log level.
		if !validLogLevel(debugLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, debugLevel)
		}

		// Change the logging level for all subsystems.
		setLogLevels(debugLevel)

		return nil
	}

	// Split the specified string into subsystem/level pairs while detecting
	// issues and update the log levels accordingly.
	for _, logLevelPair := range strings.Split(debugLevel, ",") {
		if !strings.Contains(logLevelPair, "=") {
			str := "The specified debug level contains an invalid " +
				"subsystem/level pair [%v]"
			return fmt.Errorf(str, logLevelPair)
		}

		// Extract the specified subsystem and log level.
		fields := strings.Split(logLevelPair, "=")
		subsysID, logLevel := fields[0], fields[1]

		// Validate subsystem.
		if _, exists := subsystemLoggers[subsysID]; !exists {
			str := "The specified subsystem [%v] is invalid -- " +
				"supported subsytems %v"
			return fmt.Errorf(str, subsysID, supportedSubsystems())
		}

		// Validate log level.
		if !validLogLevel(logLevel) {
			str := "The specified debug level [%v] is invalid"
			return fmt.Errorf(str, logLevel)
		}

		setLogLevel(subsysID, logLevel)
	}

	return nil
}

// validDbType returns whether or not dbType is a supported database type.
func validDbType(dbType string) bool {
	for _, knownType := range knownDbTypes {
		if dbType == knownType {
			return true
		}
	}

	return false
}

// removeDuplicateAddresses returns a new slice with all duplicate entries in
// addrs removed.
func removeDuplicateAddresses(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, val := range addrs {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = struct{}{}
		}
	}
	return result
}

// normalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func normalizeAddress(addr string, defaultPort int) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, strconv.Itoa(defaultPort))
	}
	return addr
}

// normalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func normalizeAddresses(addrs []string, defaultPort int) []string {
	for i, addr := range addrs {
		addrs[i] = normalizeAddress(addr, defaultPort)
	}

	return removeDuplicateAddresses(addrs)
}

// filesExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// createDir is used by loadConfig to create bmd home and data directories and
// report errors back, if any.
func createDir(path, name string) error {
	err := os.MkdirAll(path, 0700)
	if err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "loadConfig: Failed to create %s directory: %v"
		err := fmt.Errorf(str, name, err)
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}

// newConfigParser returns a new command line flags parser.
func newConfigParser(cfg *config, appName string, options flags.Options) *flags.Parser {
	p := flags.NewNamedParser(appName, options)

	if cfg != nil {
		p.AddGroup("Application Options", "", cfg)
	}

	return p
}

// loadConfig initializes and parses the config using a config file and command
// line options. isTest is used to ignore command line; meant to be used
// during testing.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
//
// The above results in bmd functioning properly without any config settings
// while still allowing the user to override settings with config files and
// command line options. Command line options always take precedence.
func loadConfig() (*config, []string, error) {

	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))

	return LoadConfig(appName, os.Args[1:])
}

func LoadConfig(appName string, args []string) (*config, []string, error) {
	// Default config.
	cfg := config{
		ConfigFile:      defaultConfigFile,
		DebugLevel:      defaultLogLevel,
		MaxPeers:        defaultMaxPeers,
		RPCMaxClients:   defaultMaxRPCClients,
		DataDir:         defaultDataDir,
		LogDir:          defaultLogDir,
		DbType:          defaultDbType,
		RPCKey:          defaultRPCKeyFile,
		RPCCert:         defaultRPCCertFile,
		MaxDownPerPeer:  defaultMaxDownPerPeer,
		MaxUpPerPeer:    defaultMaxUpPerPeer,
		MaxOutbound:     defaultMaxOutbound,
		RequestExpire:   defaultRequestTimeout,
		dnsSeeds:        defaultDNSSeeds,
		CleanupInterval: defaultCleanupInterval,
	}

	// Pre-parse the command line options to see if an alternative config
	// file or the version flag was specified. Any errors aside from the
	// help message error can be ignored here since they will be caught by
	// the final parse below.
	preCfg := cfg
	var err error
	preParser := newConfigParser(&preCfg, appName, flags.HelpFlag)
	_, err = preParser.ParseArgs(args)
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stderr, err)
			return nil, nil, err
		}
	}

	// Show the version and exit if the version flag was specified.
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", version())
		os.Exit(0)
	}

	// Load additional config from file.
	var configFileError error
	parser := newConfigParser(&cfg, appName, flags.Default)
	// If the default location is specified, then the file isn't required to exist.
	if preCfg.ConfigFile != defaultConfigFile || fileExists(preCfg.ConfigFile) {

		err = flags.NewIniParser(parser).ParseFile(preCfg.ConfigFile)

		if err != nil {
			if _, ok := err.(*os.PathError); !ok {
				fmt.Fprintf(os.Stderr, "Error parsing config "+
					"file: %v\n", err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
			configFileError = err
		}
	}

	// Parse command line options again to ensure they take precedence.
	var remainingArgs []string
	remainingArgs, err = parser.ParseArgs(args)
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			fmt.Fprintln(os.Stderr, usageMessage)
		}
		return nil, nil, err
	}

	funcName := "loadConfig"

	// Create the data and log directories if they don't already exist.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	err = createDir(cfg.DataDir, "data")
	if err != nil {
		return nil, nil, err
	}

	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	err = createDir(cfg.LogDir, "log")
	if err != nil {
		return nil, nil, err
	}

	// Special show command to list supported subsystems and exit.
	if cfg.DebugLevel == "show" {
		fmt.Println("Supported subsystems", supportedSubsystems())
		os.Exit(0)
	}

	// Initialize logging at the default logging level.
	initSeelogLogger(filepath.Join(cfg.LogDir, defaultLogFilename))
	setLogLevels(defaultLogLevel)

	// Parse, validate, and set debug log level(s).
	if err := parseAndSetDebugLevels(cfg.DebugLevel); err != nil {
		err := fmt.Errorf("%s: %v", funcName, err.Error())
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Validate database type.
	if !validDbType(cfg.DbType) {
		str := "%s: The specified database type [%v] is invalid -- " +
			"supported types %v"
		err := fmt.Errorf(str, funcName, cfg.DbType, knownDbTypes)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Validate profile port number
	if cfg.Profile != "" {
		profilePort, err := strconv.Atoi(cfg.Profile)
		if err != nil || profilePort < 1024 || profilePort > 65535 {
			str := "%s: The profile port must be between 1024 and 65535"
			err := fmt.Errorf(str, funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}
	}

	// Don't allow request expire times that are too short.
	if cfg.RequestExpire < time.Duration(10*time.Second) {
		str := "%s: The requestexpire option may not be less than 10s -- parsed [%v]"
		err := fmt.Errorf(str, funcName, cfg.RequestExpire)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Don't allow cleanup times that are too short.
	if cfg.CleanupInterval < time.Duration(20*time.Minute) {
		str := "%s: The cleanupinterval option may not be less than 20m -- parsed [%v]"
		err := fmt.Errorf(str, funcName, cfg.RequestExpire)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// --addPeer and --connect do not mix.
	if len(cfg.AddPeers) > 0 && len(cfg.ConnectPeers) > 0 {
		str := "%s: the --addpeer and --connect options can not be " +
			"mixed"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Attach the default initial nodes.
	cfg.AddPeers = append(cfg.AddPeers, defaultInitialNodes...)

	// --proxy or --connect without --listen disables listening.
	if (cfg.Proxy != "" || len(cfg.ConnectPeers) > 0) &&
		len(cfg.Listeners) == 0 {
		cfg.DisableListen = true
	}

	// Connect means no DNS seeding.
	if len(cfg.ConnectPeers) > 0 {
		cfg.DisableDNSSeed = true
	}

	// Add the default listener if none were specified. The default
	// listener is all addresses on the listen port for the network
	// we are to connect to.
	if len(cfg.Listeners) == 0 {
		cfg.Listeners = []string{
			net.JoinHostPort("", strconv.Itoa(defaultPort)),
		}
	}

	// Check to make sure limited and admin users don't have the same username
	if cfg.RPCUser == cfg.RPCLimitUser && cfg.RPCUser != "" {
		str := "%s: --rpcuser and --rpclimituser must not specify the " +
			"same username"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Check to make sure limited and admin users don't have the same password
	if cfg.RPCPass == cfg.RPCLimitPass && cfg.RPCPass != "" {
		str := "%s: --rpcpass and --rpclimitpass must not specify the " +
			"same password"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// The RPC server is disabled if no username or password is provided.
	if (cfg.RPCUser == "" || cfg.RPCPass == "") &&
		(cfg.RPCLimitUser == "" || cfg.RPCLimitPass == "") {
		cfg.DisableRPC = true
	}

	// Default RPC to listen on localhost only.
	if !cfg.DisableRPC && len(cfg.RPCListeners) == 0 {
		addrs, err := net.LookupHost("localhost")
		if err != nil {
			return nil, nil, err
		}
		cfg.RPCListeners = make([]string, 0, len(addrs))
		for _, addr := range addrs {
			addr = net.JoinHostPort(addr, strconv.Itoa(defaultRPCPort))
			cfg.RPCListeners = append(cfg.RPCListeners, addr)
		}
	}

	// Add default port to all listener addresses if needed and remove
	// duplicate addresses.
	cfg.Listeners = normalizeAddresses(cfg.Listeners, defaultPort)

	// Add default port to all rpc listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListeners = normalizeAddresses(cfg.RPCListeners, defaultRPCPort)

	// Only allow TLS to be disabled if the RPC is bound to localhost
	// addresses.
	if !cfg.DisableRPC && cfg.DisableTLS {
		allowedTLSListeners := map[string]struct{}{
			"localhost": struct{}{},
			"127.0.0.1": struct{}{},
			"::1":       struct{}{},
		}
		for _, addr := range cfg.RPCListeners {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				str := "%s: RPC listen interface '%s' is " +
					"invalid: %v"
				err := fmt.Errorf(str, funcName, addr, err)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
			if _, ok := allowedTLSListeners[host]; !ok {
				str := "%s: the --notls option may not be used " +
					"when binding RPC to non localhost " +
					"addresses: %s"
				err := fmt.Errorf(str, funcName, addr)
				fmt.Fprintln(os.Stderr, err)
				fmt.Fprintln(os.Stderr, usageMessage)
				return nil, nil, err
			}
		}
	}

	// Add default port to all added peer addresses if needed and remove
	// duplicate addresses.
	cfg.AddPeers = normalizeAddresses(cfg.AddPeers, defaultPort)
	cfg.ConnectPeers = normalizeAddresses(cfg.ConnectPeers, defaultPort)

	// Tor stream isolation requires either proxy or onion proxy to be set.
	if cfg.TorIsolation && cfg.Proxy == "" && cfg.OnionProxy == "" {
		str := "%s: Tor stream isolation requires either proxy or " +
			"onionproxy to be set"
		err := fmt.Errorf(str, funcName)
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, usageMessage)
		return nil, nil, err
	}

	// Setup dial and DNS resolution (lookup) functions depending on the
	// specified options.  The default is to use the standard net.Dial
	// function as well as the system DNS resolver.  When a proxy is
	// specified, the dial function is set to the proxy specific dial
	// function and the lookup is set to use tor (unless --noonion is
	// specified in which case the system DNS resolver is used).
	cfg.dial = net.Dial
	cfg.lookup = net.LookupIP
	if cfg.Proxy != "" {
		_, _, err := net.SplitHostPort(cfg.Proxy)
		if err != nil {
			str := "%s: Proxy address '%s' is invalid: %v"
			err := fmt.Errorf(str, funcName, cfg.Proxy, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}

		if cfg.TorIsolation &&
			(cfg.ProxyUser != "" || cfg.ProxyPass != "") {
			bmdLog.Warn("Tor isolation set -- overriding " +
				"specified proxy user credentials")
		}

		proxy := &socks.Proxy{
			Addr:         cfg.Proxy,
			Username:     cfg.ProxyUser,
			Password:     cfg.ProxyPass,
			TorIsolation: cfg.TorIsolation,
		}
		cfg.dial = proxy.Dial
		if !cfg.NoOnion {
			cfg.lookup = func(host string) ([]net.IP, error) {
				return torLookupIP(host, cfg.Proxy)
			}
		}
	}

	// Setup onion address dial and DNS resolution (lookup) functions
	// depending on the specified options.  The default is to use the
	// same dial and lookup functions selected above.  However, when an
	// onion-specific proxy is specified, the onion address dial and
	// lookup functions are set to use the onion-specific proxy while
	// leaving the normal dial and lookup functions as selected above.
	// This allows .onion address traffic to be routed through a different
	// proxy than normal traffic.
	if cfg.OnionProxy != "" {
		_, _, err := net.SplitHostPort(cfg.OnionProxy)
		if err != nil {
			str := "%s: Onion proxy address '%s' is invalid: %v"
			err := fmt.Errorf(str, funcName, cfg.OnionProxy, err)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, nil, err
		}

		if cfg.TorIsolation &&
			(cfg.OnionProxyUser != "" || cfg.OnionProxyPass != "") {
			bmdLog.Warn("Tor isolation set -- overriding " +
				"specified onionproxy user credentials ")
		}

		cfg.oniondial = func(a, b string) (net.Conn, error) {
			proxy := &socks.Proxy{
				Addr:         cfg.OnionProxy,
				Username:     cfg.OnionProxyUser,
				Password:     cfg.OnionProxyPass,
				TorIsolation: cfg.TorIsolation,
			}
			return proxy.Dial(a, b)
		}
		cfg.onionlookup = func(host string) ([]net.IP, error) {
			return torLookupIP(host, cfg.OnionProxy)
		}
	} else {
		cfg.oniondial = cfg.dial
		cfg.onionlookup = cfg.lookup
	}

	// Specifying --noonion means the onion address dial and DNS resolution
	// (lookup) functions result in an error.
	if cfg.NoOnion {
		cfg.oniondial = func(a, b string) (net.Conn, error) {
			return nil, errors.New("tor has been disabled")
		}
		cfg.onionlookup = func(a string) ([]net.IP, error) {
			return nil, errors.New("tor has been disabled")
		}
	}

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid options.
	// Note this should go directly before the return.
	if configFileError != nil {
		bmdLog.Warnf("%v", configFileError)
	}

	return &cfg, remainingArgs, nil
}

// bmdDial connects to the address on the named network using the appropriate
// dial function depending on the address and configuration options.  For
// example, .onion addresses will be dialed using the onion specific proxy if
// one was specified, but will otherwise use the normal dial function (which
// could itself use a proxy or not).
func bmdDial(network, address string) (net.Conn, error) {
	if strings.Contains(address, ".onion:") {
		return cfg.oniondial(network, address)
	}
	return cfg.dial(network, address)
}

// bmdLookup returns the correct DNS lookup function to use depending on the
// passed host and configuration options.  For example, .onion addresses will be
// resolved using the onion specific proxy if one was specified, but will
// otherwise treat the normal proxy as tor unless --noonion was specified in
// which case the lookup will fail.  Meanwhile, normal IP addresses will be
// resolved using tor if a proxy was specified unless --noonion was also
// specified in which case the normal system DNS resolver will be used.
func bmdLookup(host string) ([]net.IP, error) {
	if strings.HasSuffix(host, ".onion") {
		return cfg.onionlookup(host)
	}
	return cfg.lookup(host)
}
