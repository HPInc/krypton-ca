// package github.com/HPInc/krypton-ca/service
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Entry point for unit tests for the Krypton certificate authority.
package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/HPInc/krypton-ca/service/common"
	"github.com/HPInc/krypton-ca/service/config"
)

func TestMain(m *testing.M) {
	testModeEnabled := true
	initLogger("debug")

	cfgMgr = config.NewConfigMgr(caLogger, common.ServiceName)
	if !cfgMgr.Load(testModeEnabled) {
		caLogger.Error("Error loading configuration. Exiting!")
		shutdownLogger()
		os.Exit(2)
	}

	retCode := m.Run()
	fmt.Println("Finished running the certificate authority unit tests!")
	shutdownLogger()
	os.Exit(retCode)
}
