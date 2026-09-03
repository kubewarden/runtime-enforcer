package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kubewarden/runtime-enforcer/internal/tlsutil"
	"github.com/kubewarden/runtime-enforcer/internal/types/otlp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/credentials"
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

func createMetricGRPCExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdkmetric.Exporter, error) {
	// if the user specified the correct path we shouldn't receive the http prefix here, but just to be sure.
	gRPCEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")
	insecure := caCertPath == ""
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(gRPCEndpoint),
		otlpmetricgrpc.WithTemporalitySelector(gaugeDeltaTemporality),
	}
	if insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	} else {
		tlsConfig, err := tlsutil.BuildTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
	}
	return otlpmetricgrpc.New(ctx, opts...)
}

func createMetricHTTPExporter(ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath string,
) (sdkmetric.Exporter, error) {
	// first we check if we are in insecure mode
	insecure := strings.HasPrefix(endpoint, "http://")
	// Strip the scheme from the endpoint: WithEndpoint expects "host:port".
	httpEndpoint := strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://")

	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(httpEndpoint),
		otlpmetrichttp.WithTemporalitySelector(gaugeDeltaTemporality),
	}

	if insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	} else if caCertPath != "" {
		tlsConfig, err := tlsutil.BuildTLSConfig(caCertPath, clientCertPath, clientKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(tlsConfig))
	}
	return otlpmetrichttp.New(ctx, opts...)
}

// Init creates an OTEL meter provider that pushes controller metrics to the
// given OTLP endpoint and registers the active-violations gauge. The protocol
// can be either "grpc" or "http/protobuf". When caCertPath is non-empty, the
// connection verifies the collector's certificate against the provided CA;
// otherwise insecure mode is used. When clientCertPath and clientKeyPath are
// both non-empty, the client presents a TLS certificate for mTLS authentication.
// exportInterval controls how often the PeriodicReader pushes recorded gauges
// to the collector (typically the same as the status-sync update interval).
func Init(
	ctx context.Context,
	endpoint, caCertPath, clientCertPath, clientKeyPath, protocol string,
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
		exporter, err = createMetricGRPCExporter(ctx, endpoint, caCertPath, clientCertPath, clientKeyPath)
	case otlp.HTTPProtobuf:
		exporter, err = createMetricHTTPExporter(ctx, endpoint, caCertPath, clientCertPath, clientKeyPath)
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
