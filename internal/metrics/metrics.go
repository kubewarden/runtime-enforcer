package metrics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/kubewarden/runtime-enforcer/internal/types/otlp"
)

const (
	activeViolationsMetricName = "runtime_enforcer_active_violations"
	meterName                  = "active-violations-reporter"
)

// gaugeDeltaTemporality uses delta temporality for sync gauges so attribute
// sets that are no longer recorded (pruned policies) are dropped on collect.
func gaugeDeltaTemporality(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	if kind == sdkmetric.InstrumentKindGauge {
		return metricdata.DeltaTemporality
	}
	return sdkmetric.DefaultTemporalitySelector(kind)
}

// Init creates an OTEL meter provider that pushes controller metrics to an
// OTLP collector and registers the active-violations gauge. The protocol
// can be "grpc" or "http/protobuf". An empty protocol means "grpc".
//
// The exporter reads its connection settings
// from the OTEL_EXPORTER_OTLP_* environment variables.
//
// exportInterval controls how often the PeriodicReader pushes recorded gauges
// to the collector (typically the same as the status-sync update interval).
func Init(
	ctx context.Context,
	protocol string,
	exportInterval time.Duration,
) (metric.Int64Gauge, func(context.Context) error, error) {
	if exportInterval <= 0 {
		return nil, nil, fmt.Errorf("invalid metrics export interval: %v", exportInterval)
	}

	var exporter sdkmetric.Exporter
	proto, err := otlp.Parse(protocol)
	if err != nil {
		return nil, nil, err
	}
	switch proto {
	case otlp.GRPC:
		exporter, err = otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithTemporalitySelector(gaugeDeltaTemporality))
	case otlp.HTTPProtobuf:
		exporter, err = otlpmetrichttp.New(ctx, otlpmetrichttp.WithTemporalitySelector(gaugeDeltaTemporality))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
	}

	periodicReader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(exportInterval))
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(periodicReader))

	gauge, regErr := provider.Meter(meterName).Int64Gauge(
		activeViolationsMetricName,
		metric.WithDescription(
			"Current number of active violations per WorkloadPolicy, "+
				"read from status.activeViolationCount",
		),
	)
	if regErr != nil {
		regErr = fmt.Errorf("failed to register %s gauge: %w", activeViolationsMetricName, regErr)
		return nil, nil, errors.Join(regErr, provider.Shutdown(ctx))
	}

	return gauge, provider.Shutdown, nil
}
