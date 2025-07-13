// package github.com/HPInc/krypton-ca/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Initialize the HTTP REST server for the CA service.
package rest

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HPInc/krypton-ca/service/config"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

var (
	caLogger             *zap.Logger
	debugLogRestRequests bool
)

const (
	// HTTP server timeouts for the REST endpoint.
	readTimeout  = (time.Second * 5)
	writeTimeout = (time.Second * 5)
)

// Represents the CA REST service.
type caRestService struct {
	// Signal handling to support SIGTERM and SIGINT for the service.
	errChannel  chan error
	stopChannel chan os.Signal

	// Prometheus metrics reporting.
	metricRegistry *prometheus.Registry

	// Request router
	router *mux.Router

	// HTTP port on which the REST server is available.
	port int
}

// Creates a new instance of the CA REST service and initalizes the request
// router for the CA REST endpoint.
func newCaRestService() *caRestService {
	s := &caRestService{}

	// Initial signal handling.
	s.errChannel = make(chan error)
	s.stopChannel = make(chan os.Signal, 1)
	signal.Notify(s.stopChannel, syscall.SIGINT, syscall.SIGTERM)

	// Initialize the prometheus metric reporting registry.
	s.metricRegistry = prometheus.NewRegistry()

	s.router = initRequestRouter()
	return s
}

// Starts the HTTP REST server for the CA service and starts serving requests
// at the REST endpoint.
func (s *caRestService) startServing() {
	// Start the HTTP REST server. http.ListenAndServe() always returns
	// a non-nil error
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", s.port),
		Handler:        s.router,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		MaxHeaderBytes: 1 << 20,
	}

	err := server.ListenAndServe()
	caLogger.Error("Received a fatal error from http.ListenAndServe",
		zap.Error(err),
	)

	// Signal the error channel so we can shutdown the service.
	s.errChannel <- err
}

// Waits for the CA REST server to be terminated - either in response to a
// system event received on the stop channel or a fatal error signal received
// on the error channel.
func (s *caRestService) awaitTermination() {
	select {
	case err := <-s.errChannel:
		caLogger.Error("Shutting down due to a fatal error.",
			zap.Error(err),
		)
	case sig := <-s.stopChannel:
		caLogger.Info("Received an OS signal to shut down!",
			zap.String("Signal received: ", sig.String()),
		)
	}
}

// Init initializes the CA REST server and starts serving REST requests at the
// CA's REST endpoint.
func Init(logger *zap.Logger, cfgMgr *config.ConfigMgr) {
	caLogger = logger
	debugLogRestRequests = cfgMgr.GetServerConfig().DebugLogRestRequests

	s := newCaRestService()
	s.port = cfgMgr.GetServerConfig().RestPort

	// Initialize the REST server and listen for REST requests on a separate
	// goroutine. Report fatal errors via the error channel.
	go s.startServing()
	caLogger.Info("Started the CA REST service!",
		zap.Int("Port: ", s.port),
	)

	// Wait for the REST server to be terminated either in response to a system
	// event (like service shutdown) or a fatal error.
	s.awaitTermination()
}
