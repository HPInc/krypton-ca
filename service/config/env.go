// package github.com/HPInc/krypton-ca/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Certificate Authority
// (C) HP Development Company, LP
// Purpose:
// Retrieves configured environment variables for the CA service and overrides
// appropriate configuration settings.
package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/HPInc/krypton-ca/service/common"
	"go.uber.org/zap"
)

type value struct {
	secret bool
	v      interface{}
}

// loadEnvironmentVariableOverrides - check values specified for supported
// environment variables. These can be used to override configuration settings
// specified in the config file.
func overrideFromEnvironment(c *Config) {
	m := map[string]value{
		//Server
		"CA_SERVER":                  {v: &c.Server.Host},
		"CA_RPC_PORT":                {v: &c.Server.RpcPort},
		"CA_REST_PORT":               {v: &c.Server.RestPort},
		"CA_DEBUG_LOG_REST_REQUESTS": {v: &c.DebugLogRestRequests},

		// Certificate authority configuration settings
		"CA_KMS_PROVIDER":               {v: &c.CertificateAuthority.KmsProvider},
		"CA_CERT_STORE_PROVIDER":        {v: &c.CertificateAuthority.CertStoreProvider},
		"CA_PER_TENANT_SIGNING_ENABLED": {v: &c.CertificateAuthority.PerTenantSigningEnabled},

		// Check if test mode needs to be enabled - this may cause certain test hooks
		// to be enabled - this must not be specified in production.
		"CA_TEST_MODE": {v: &c.TestMode},
	}
	for k, v := range m {
		e := os.Getenv(k)
		if e != "" {
			caLogger.Info("Overriding configuration from environment variable.",
				zap.String("variable: ", k),
				zap.String("value: ", getLoggableValue(v.secret, e)))
			v := v
			replaceConfigValue(os.Getenv(k), &v)
		}
	}
}

// envValue will be non empty as this function is private to file
func replaceConfigValue(envValue string, t *value) {
	switch t.v.(type) {
	case *string:
		*t.v.(*string) = envValue
	case *[]string:
		valSlice := strings.Split(envValue, ",")
		for i := range valSlice {
			valSlice[i] = strings.TrimSpace(valSlice[i])
		}
		*t.v.(*[]string) = valSlice
	case *bool:
		b, err := strconv.ParseBool(envValue)
		if err != nil {
			caLogger.Error("Bad bool value in env")
		} else {
			*t.v.(*bool) = b
		}
	case *int:
		i, err := strconv.Atoi(envValue)
		if err != nil {
			caLogger.Error("Bad integer value in env",
				zap.Error(err))
		} else {
			*t.v.(*int) = i
		}
	default:
		caLogger.Error("There was a bad type map in env override",
			zap.String("value", envValue))
	}
}

func getLoggableValue(secret bool, value string) string {
	if secret {
		return "***"
	}
	return value
}

// loadEnvironmentVariableOverrides - check values specified for supported
// environment variables. These can be used to override configuration settings
// specified in the config file.
func (c *ConfigMgr) loadEnvironmentVariableOverrides() error {

	// override config from environment variables
	// note this only happens if environment variables are specified
	overrideFromEnvironment(&c.config)

	// Determine if the configuration requests a valid KMS provider.
	switch c.config.CertificateAuthority.KmsProvider {
	case common.KmsProviderAws, common.KmsProviderLocal:
		break
	default:
		return common.ErrInvalidKmsProvider
	}

	// Determine if the configuration requests a valid cert store provider.
	switch c.config.CertificateAuthority.CertStoreProvider {
	case common.CertStoreDynamoDb, common.CertStoreLocalDb:
		break
	default:
		return common.ErrInvalidCertStore
	}
	return nil
}
