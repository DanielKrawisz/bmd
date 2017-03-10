// Copyright 2016 Daniel Krawisz.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func setup(dataDir string, defaultConfigContents, configFileContents, configFilename *string) error {
	var err error

	defaultConfigFile := filepath.Join(dataDir, defaultConfigFilename)

	// Check if defaultConfigContents is set. If so, make a config file.
	if defaultConfigContents != nil {
		err = ioutil.WriteFile(defaultConfigFile, []byte(*defaultConfigContents), 0644)
		if err != nil {
			return nil
		}
	}

	// Check if configFilePath is set and is not equal to the default
	// path.
	if configFilename == nil || *configFilename == defaultConfigFilename {
		return nil
	}

	configFile := filepath.Join(dataDir, *configFilename)

	// If the file exists, remove it.
	if _, err = os.Stat(configFile); !os.IsNotExist(err) {
		err = os.Remove(configFile)
		if err != nil {
			return err
		}
	}

	if configFileContents != nil {
		err = ioutil.WriteFile(configFile, []byte(*configFileContents), 0644)
		if err != nil {
			return nil
		}
	}

	return nil
}

func testConfig(t *testing.T, testID int, expected uint64, cmdLine *uint64, defaultConfig *uint64, config *uint64, configFile *string) {
	var defaultConfigContents *string
	var configFileContents *string
	var commandLine []string

	// Ensures that the temp directory is deleted.
	Config := DefaultConfig()
	defer resetCfg(Config)()

	// first construct the command-line arguments.
	if cmdLine != nil {
		commandLine = append(commandLine, fmt.Sprintf("--maxpeers=%s", strconv.FormatUint(*cmdLine, 10)))
	}
	if configFile != nil {
		commandLine = append(commandLine, fmt.Sprintf("--configfile=%s", *configFile))
	}

	// Make the default config file.
	if defaultConfig != nil {
		dcc := fmt.Sprintf("maxpeers=%s", strconv.FormatUint(*defaultConfig, 10))
		defaultConfigContents = &dcc
	}

	// Make the extra config file.
	if config != nil {
		cc := fmt.Sprintf("maxpeers=%s", strconv.FormatUint(*config, 10))
		configFileContents = &cc
	}

	// Set up the test.
	err := setup(Config.DataDir, defaultConfigContents, configFileContents, configFile)
	if err != nil {
		t.Fail()
	}

	_, err = LoadConfig("test", Config, commandLine)

	if err != nil {
		t.Errorf("Error, test id %d: nil config returned! %s", testID, err.Error())
		return
	}

	if Config.MaxPeers != int(expected) {
		t.Errorf("Error, test id %d: expected %d got %d.", testID, expected, cfg.MaxPeers)
	}

}

func TestLoadConfig(t *testing.T) {

	// Test that an option is correctly set by default when
	// no such option is specified in the default config file
	// or on the command line.
	testConfig(t, 1, defaultMaxPeers, nil, nil, nil, nil)

	// Test that an option is correctly set when specified
	// on the command line.
	var q uint64 = 97
	testConfig(t, 2, q, &q, nil, nil, nil)

	// Test that an option is correctly set when specified
	// in the default config file without a command line
	// option set.
	file := "altbmd.conf"
	testConfig(t, 3, q, nil, &q, nil, nil)
	testConfig(t, 4, q, nil, nil, &q, &file)

	// Test that an option is correctly set when specified
	// on the command line and that it overwrites the
	// option in the config file.
	var z uint64 = 39
	testConfig(t, 5, q, &q, &z, nil, nil)
	testConfig(t, 6, q, &q, nil, &z, &file)
}
