// package github.com/HPInc/krypton-ca/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Provides a way to retrieve the various configuration settings for the
// CA service.
package config

import (
	"fmt"
	"os"

	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

const (
	// Path to the configuration YAML file.
	defaultConfigFilePath = "config.yaml"
)

var (
	caLogger *zap.Logger
)

// ConfigMgr represents configuration settings for the CA service. It
// provides a way for other packages within the CA to retrieve currently
// configured configuration settings for the service.
type ConfigMgr struct {
	config      Config
	serviceName string
}

// NewConfigMgr - initalize a new configuration manager instance.
func NewConfigMgr(logger *zap.Logger, serviceName string) *ConfigMgr {
	caLogger = logger
	return &ConfigMgr{
		serviceName: serviceName,
	}
}

// Load configuration information from the YAML configuration file.
func (c *ConfigMgr) Load(testModeEnabled bool) bool {
	var filename string = defaultConfigFilePath

	// Check if the default configuration file has been overridden using the
	// environment variable.
	c.config.ConfigFilePath = os.Getenv("DSTS_CONFIG_LOCATION")
	if c.config.ConfigFilePath != "" {
		caLogger.Info("Using configuration file specified by command line switch.",
			zap.String("Configuration file:", c.config.ConfigFilePath),
		)
		filename = c.config.ConfigFilePath
	}

	// Open the configuration file for parsing.
	fh, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Failed to open configuration file: %s. Error: %v\n!",
			filename, err)
		return false
	}

	// Read the configuration file and unmarshal the YAML.
	decoder := yaml.NewDecoder(fh)
	err = decoder.Decode(&c.config)
	if err != nil {
		fmt.Printf("Failed to parse configuration file: %s. Error: %v\n!",
			filename, err)
		_ = fh.Close()
		return false
	}

	_ = fh.Close()
	fmt.Printf("Parsed configuration from the configuration file: %s!\n", filename)

	// Load any configuration overrides specified using environment variables.
	err = c.loadEnvironmentVariableOverrides()
	if err != nil {
		return false
	}

	// Validate the provided certificate template settings.
	if !c.validateCertificateTemplateSettings() {
		fmt.Printf("Configuration settings for the certificate template are invalid! Cannot continue.")
		return false
	}

	c.Display()
	return true
}

// GetKmsProvider returns the configured key management service (KMS) provider.
func (c *ConfigMgr) GetKmsProvider() string {
	return c.config.CertificateAuthority.KmsProvider
}

// GetCertStoreProvider returns the configured certificate store provider
// settings.
func (c *ConfigMgr) GetCertStoreProvider() string {
	return c.config.CertificateAuthority.CertStoreProvider
}

// GetServerConfig returns the CA server configuration settings.
func (c *ConfigMgr) GetServerConfig() *Server {
	return &c.config.Server
}

// IsPerTenantSigningEnabled checks if per-tenant signing certificates are
// enabled for the CA.
func (c *ConfigMgr) IsPerTenantSigningEnabled() bool {
	return c.config.CertificateAuthority.PerTenantSigningEnabled
}

// IsTestModeEnabled checks if the service is running in test mode.
func (c *ConfigMgr) IsTestModeEnabled() bool {
	return c.config.TestMode
}

// GetIssuerName returns the certificate authority's issuer name.
func (c *ConfigMgr) GetIssuerName() string {
	return c.config.CertificateAuthority.IssuerName
}

// GetCertificateTemplateConfig returns the certificate template
// configuration settings.
func (c *ConfigMgr) GetCertificateTemplateConfig() *common.CertTemplateConfig {
	return &c.config.CertificateAuthority.CertTemplateConfig
}

// Validate that the configuration file specifies all configuration settings that
// are required for the certificate template.
func (c *ConfigMgr) validateCertificateTemplateSettings() bool {
	if (c.config.CertificateAuthority.CertTemplateConfig.IssuerName == "") ||
		(c.config.CertificateAuthority.CertTemplateConfig.Country == "") ||
		(c.config.CertificateAuthority.CertTemplateConfig.Province == "") ||
		(c.config.CertificateAuthority.CertTemplateConfig.Locality == "") ||
		(c.config.CertificateAuthority.CertTemplateConfig.StreetAddress == "") ||
		(c.config.CertificateAuthority.CertTemplateConfig.PostalCode == "") ||
		(c.config.CertificateAuthority.CertTemplateConfig.Organization == "") {
		return false
	}
	return true
}

// Display the configuration information parsed from the configuration file in
// the structured log.
func (c *ConfigMgr) Display() {
	caLogger.Info("Krypton Certificate Authority - current configuration",
		zap.String(" - Service name:", c.serviceName),
		zap.Bool(" - Test mode enabled:", c.config.TestMode),
	)
	caLogger.Info("Server settings",
		zap.String(" - Hostname:", c.config.Server.Host),
		zap.Int(" - RPC Port:", c.config.Server.RpcPort),
		zap.Int(" - REST Port:", c.config.Server.RestPort),
		zap.Bool(" - Request logging enabled:", c.config.DebugLogRestRequests),
	)
	caLogger.Info("Certificate authority settings",
		zap.String(" - KMS provider:", c.config.CertificateAuthority.KmsProvider),
		zap.String(" - Certificate store:", c.config.CertificateAuthority.CertStoreProvider),
		zap.String(" - Certificate Issuer:", c.config.CertificateAuthority.CertTemplateConfig.IssuerName),
		zap.String(" - Country:", c.config.CertificateAuthority.CertTemplateConfig.Country),
		zap.String(" - Province:", c.config.CertificateAuthority.CertTemplateConfig.Province),
		zap.String(" - Locality:", c.config.CertificateAuthority.CertTemplateConfig.Locality),
		zap.String(" - Street address:", c.config.CertificateAuthority.CertTemplateConfig.StreetAddress),
		zap.String(" - Postal code:", c.config.CertificateAuthority.CertTemplateConfig.PostalCode),
		zap.String(" - Organization:", c.config.CertificateAuthority.CertTemplateConfig.Organization),
	)
}
