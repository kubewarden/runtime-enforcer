package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestInit(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		protocol       string
		exportInterval time.Duration
		wantErr        bool
	}{
		{
			name:           "invalid protocol",
			protocol:       "udp",
			exportInterval: 30 * time.Second,
			wantErr:        true,
		},
		{
			name:           "invalid export interval",
			protocol:       "grpc",
			exportInterval: 0,
			wantErr:        true,
		},
		{
			name:           "empty protocol means grpc",
			protocol:       "",
			exportInterval: 30 * time.Second,
		},
		{
			name:           "grpc",
			protocol:       "grpc",
			exportInterval: 30 * time.Second,
		},
		{
			name:           "http/protobuf",
			protocol:       "http/protobuf",
			exportInterval: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
			gauge, shutdown, err := Init(ctx, tt.protocol, tt.exportInterval)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, gauge)
				require.Nil(t, shutdown)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, gauge)
			require.NotNil(t, shutdown)
			shutdownProvider(t, shutdown)
		})
	}
}

func TestGaugeDeltaTemporality(t *testing.T) {
	require.Equal(t, metricdata.DeltaTemporality, gaugeDeltaTemporality(sdkmetric.InstrumentKindGauge))
	require.Equal(t, metricdata.CumulativeTemporality, gaugeDeltaTemporality(sdkmetric.InstrumentKindCounter))
}

// shutdownProvider tears down the meter provider. Export may fail when no
// collector is listening; that is expected in unit tests.
func shutdownProvider(t *testing.T, shutdown func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = shutdown(ctx)
}
