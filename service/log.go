// package github.com/HPInc/krypton-ca/service
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Initializes and configures structured logging for the CA service. We use
// Uber Zap for structured logging.
package main

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	caLogger *zap.Logger
	logLevel zap.AtomicLevel
)

// Initialize structured logging for the CA service using Uber Zap.
func initLogger(levelString string) {
	// Log to the console by default.
	logLevel = zap.NewAtomicLevel()
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		logLevel)
	logger := zap.New(core, zap.AddCaller())
	caLogger = logger
	setLogLevel(levelString)
}

// Shutdown structured logging for the CA service.
func shutdownLogger() {
	_ = caLogger.Sync()
}

// Configures the logging level for the CA service. The default log level is
// the info level. Allowable levels are defined in the zapcore package.
func setLogLevel(level string) {
	parsedLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		// Fallback to logging at the info level.
		fmt.Printf("Falling back to the info log level. You specified: %s.\n",
			level)
		logLevel.SetLevel(zapcore.InfoLevel)
	} else {
		logLevel.SetLevel(parsedLevel)
	}
}
