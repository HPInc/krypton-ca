// package github.com/HPInc/krypton-ca/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Defines the REST routes and their corresponding HTTP handler functions
// registered with the Gorilla MUX router for the CA REST server.
package rest

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Route - used to route REST requests received by the service.
type Route struct {
	Name        string           // Name of the route
	Method      string           // REST method
	Path        string           // Resource path
	HandlerFunc http.HandlerFunc // Request handler function.
}

type routes []Route

// List of registered REST routes and corresponding HTTP handler functions
// used to serve requests at those routes.
var registeredRoutes = routes{
	// Health endpoint.
	Route{
		"GetHealth",
		"GET",
		"/health",
		GetHealthHandler,
	},

	// Metrics endpoint.
	Route{
		"GetMetrics",
		"GET",
		"/metrics",
		promhttp.Handler().(http.HandlerFunc),
	},
}
