package traces

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	traceSDK "go.opentelemetry.io/otel/sdk/trace"
)

// Init creates an otel trace provider based on environment variables
// and set it as the global one.
func Init() (func(context.Context) error, error) {
	ctx := context.Background()

	// This command reads the configuration from otel environment variables, e.g., OTEL_EXPORTER_OTLP_ENDPOINT.
	exporter, err := otlptracegrpc.New(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to create exporter: %w", err)
	}
	traceProvider := traceSDK.NewTracerProvider(
		traceSDK.WithBatcher(exporter),
	)
	otel.SetTracerProvider(traceProvider)

	return traceProvider.Shutdown, nil
}
