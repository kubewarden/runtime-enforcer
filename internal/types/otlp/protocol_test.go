package otlp_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kubewarden/runtime-enforcer/internal/types/otlp"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    otlp.Protocol
		wantErr bool
	}{
		{name: "empty means grpc", input: "", want: otlp.GRPC},
		{name: "grpc", input: "grpc", want: otlp.GRPC},
		{name: "http/protobuf", input: "http/protobuf", want: otlp.HTTPProtobuf},
		{name: "unknown", input: "udp", wantErr: true},
		{name: "http/json is not supported", input: "http/json", wantErr: true},
		{name: "case sensitive", input: "GRPC", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := otlp.Parse(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{name: "http", endpoint: "http://collector:4317"},
		{name: "https", endpoint: "https://collector.example.com:4317"},
		{name: "https with path", endpoint: "https://collector.example.com/otlp"},
		{name: "uppercase scheme", endpoint: "HTTPS://collector:4317"},
		{name: "ip address", endpoint: "http://10.0.0.1:4317"},
		{name: "ipv6 address", endpoint: "http://[::1]:4317"},
		{name: "no scheme", endpoint: "collector:4317", wantErr: true},
		{name: "localhost without scheme", endpoint: "localhost:4317", wantErr: true},
		{name: "ip address without scheme", endpoint: "10.0.0.1:4317", wantErr: true},
		{name: "unsupported scheme", endpoint: "dns:///collector:4317", wantErr: true},
		{name: "no host", endpoint: "https://", wantErr: true},
		{name: "port without host", endpoint: "http://:4317", wantErr: true},
		{name: "https port without host", endpoint: "https://:4317", wantErr: true},
		{name: "empty", endpoint: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := otlp.ValidateEndpoint(tt.endpoint)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
