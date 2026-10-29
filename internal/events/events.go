package events

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/kubewarden/runtime-enforcer/internal/types/otlp"
)

// Init creates an OTEL log provider that exports violation events to an
// OTLP collector. The protocol can be "grpc" or "http/protobuf".
// An empty protocol means "grpc".
//
// The exporter reads its connection settings
// from the OTEL_EXPORTER_OTLP_* environment variables.
func Init(ctx context.Context, protocol string) (otellog.Logger, func(context.Context) error, error) {
	var exporter sdklog.Exporter
	proto, err := otlp.Parse(protocol)
	if err != nil {
		return nil, nil, err
	}
	switch proto {
	case otlp.GRPC:
		exporter, err = otlploggrpc.New(ctx)
	case otlp.HTTPProtobuf:
		exporter, err = otlploghttp.New(ctx)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OTLP log exporter: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	logger := provider.Logger("violation-reporter")
	return logger, provider.Shutdown, nil
}
