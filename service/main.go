// package github.com/HPInc/krypton-ca/service
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Entry point for the Krypton Certificate Authority service. Various
// components of the CA service are initialized and configured from here.
// In response to a shutdown signal or fatal errors, the service is stopped.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/HPInc/krypton-ca/service/certmgr"
	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/config"
	"github.com/HPInc/krypton-ca/service/rest"
	"github.com/HPInc/krypton-ca/service/rpc"
	"go.uber.org/zap"
)

var (
	// --version: displays versioning information.
	versionFlag = flag.Bool("version", false,
		"Print the version of the service and exit!")

	// --log_level: specify the logging level to use.
	logLevelFlag = flag.String("log_level", "", "Specify the logging level.")

	// Versioning information.
	gitCommitHash string
	builtAt       string
	builtBy       string
	builtOn       string

	// Service configuration settings.
	cfgMgr *config.ConfigMgr
)

// Display version information for the CA service's binary.
func printVersionInformation() {
	fmt.Println("Krypton Certificate Authority: version information")
	fmt.Printf("- Git commit hash: %s\n - Built at: %s\n - Built by: %s\n - Built on: %s\n",
		gitCommitHash, builtAt, builtBy, builtOn)
}

func main() {
	var err error

	// Parse the command line flags.
	flag.Parse()
	if *versionFlag {
		printVersionInformation()
		return
	}

	// Initialize structured logging.
	initLogger(*logLevelFlag)

	// Read and parse the configuration file.
	cfgMgr = config.NewConfigMgr(caLogger, common.ServiceName)
	if !cfgMgr.Load(false) {
		shutdownLogger()
		os.Exit(2)
	}

	// Set the default log level.
	setLogLevel(*logLevelFlag)

	// Initialize the certificate authority.
	certProvider, err := certmgr.Init(caLogger, cfgMgr)
	if err != nil {
		caLogger.Error("Failed to initialize the certificate authority!",
			zap.Error(err),
		)
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize the REST server and listen for requests on a separate
	// goroutine.
	go rest.Init(caLogger, cfgMgr)

	// Initialize the gRPC server and start listening for RPC requests at the
	// certificate authority endpoint.
	err = rpc.Init(caLogger, cfgMgr.GetServerConfig(), certProvider)
	if err != nil {
		caLogger.Error("Failed to initialize the gRPC server!",
			zap.Error(err),
		)
		shutdownLogger()
		os.Exit(2)
	}

	shutdownLogger()
	fmt.Println("Krypton Certificate Authority: Goodbye!")
}
