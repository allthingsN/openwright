package openwrightexporter

import "errors"

// Config is the configuration for the OpenWright evidence exporter.
//
// The exporter forwards a copy of the telemetry to a `openwright collector` running
// as an evidence sink. Per docs/OTEL_PROCESSOR_SCOPE.md the cryptographic core
// stays a single byte-exact Python implementation; this component is a thin,
// native OpenTelemetry forwarder, not a second crypto implementation.
type Config struct {
	// Endpoint is the base URL of the OpenWright sink (e.g. http://127.0.0.1:4318).
	// "/v1/traces" is appended automatically.
	Endpoint string `mapstructure:"endpoint"`
}

func (c *Config) Validate() error {
	if c.Endpoint == "" {
		return errors.New("openwright exporter: endpoint must be set")
	}
	return nil
}
