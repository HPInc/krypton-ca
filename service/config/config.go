// package github.com/HPInc/krypton-ca/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Represents configuration setings for the Krypton CA service.
package config

import "github.com/HPInc/krypton-ca/service/common"

// Server represents contains configuration settings for the CA servers.
// This includes the gRPC server and the REST/HTTP server.
type Server struct {
	// Hostname of the CA service.
	Host string `yaml:"host"`

	// Port on which the gRPC server is available.
	RpcPort int `yaml:"rpc_port"`

	// Port on which the REST server is available.
	RestPort int `yaml:"rest_port"`

	// Specifies whether to log all incoming REST requests to the debug log.
	DebugLogRestRequests bool `yaml:"log_rest_requests"`
}

// Config represents configuration settings for the CA service.
type Config struct {
	ConfigFilePath string

	// Configuration settings for the gRPC and REST servers.
	Server `yaml:"server"`

	// CertificateAuthority configuration settings.
	CertificateAuthority struct {
		// Key Management service provider to be used.
		KmsProvider string `yaml:"kms_provider"`

		// Certificate store to be used to store signing certificates.
		CertStoreProvider string `yaml:"cert_store"`

		// Whether per-tenant signing keys should be used. If this is set
		// to false, the common signing certificate is used to sign all
		// device certificates.
		PerTenantSigningEnabled bool `yaml:"per_tenant_signing"`

		// Certificate template configuration settings.
		common.CertTemplateConfig `yaml:"cert_template"`

		// Populated after reading the AWS_ACCESS_KEY_ID environment
		// variable. For security reasons, this may not be specified using
		// the configuration YAML file.
		AwsAccessKeyId string

		// Populated after reading the AWS_SECRET_ACCESS_KEY environment
		// variable. For security reasons, this may not be specified using
		// the configuration YAML file.
		AwsSecretAccessKey string
	} `yaml:"certificate_authority"`

	// Whether the CA is configured to run in test mode.
	TestMode bool `yaml:"test_mode"`
}
