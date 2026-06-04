// Package openwrightexporter is a native OpenTelemetry Collector exporter that
// forks a copy of trace telemetry to an OpenWright evidence sink. It lets a team
// add OpenWright to a Collector they already run by configuring an `openwright`
// exporter, instead of hand-wiring a generic otlphttp exporter.
package openwrightexporter

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
)

var componentType = component.MustNewType("openwright")

const stability = component.StabilityLevelAlpha

// NewFactory returns the factory for the OpenWright exporter.
func NewFactory() exporter.Factory {
	return exporter.NewFactory(
		componentType,
		createDefaultConfig,
		exporter.WithTraces(createTraces, stability),
	)
}

func createDefaultConfig() component.Config {
	return &Config{Endpoint: "http://127.0.0.1:4318"}
}

func createTraces(
	ctx context.Context,
	set exporter.Settings,
	cfg component.Config,
) (exporter.Traces, error) {
	c := cfg.(*Config)
	e := newOpenWrightExporter(c)
	return exporterhelper.NewTraces(ctx, set, cfg, e.pushTraces)
}
