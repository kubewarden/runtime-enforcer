package otlp

import (
	"fmt"
	"net/url"
)

type Protocol string

const (
	GRPC         Protocol = "grpc"
	HTTPProtobuf Protocol = "http/protobuf"
)

// Parse returns the protocol for s.
// An empty string means gRPC, the default protocol.
func Parse(s string) (Protocol, error) {
	switch Protocol(s) {
	case "":
		return GRPC, nil
	case GRPC, HTTPProtobuf:
		return Protocol(s), nil
	default:
		return "", fmt.Errorf("unsupported protocol %q (supported: %q, %q)", s, GRPC, HTTPProtobuf)
	}
}

// ValidateEndpoint returns an error when endpoint is not an http:// or https:// URL with a host.
// The OpenTelemetry SDK accepts an endpoint without a scheme, such as "collector:4317",
// but the gRPC log exporter then loses the address and every export fails.
func ValidateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf(
			"invalid OTLP endpoint %q: use an http:// or https:// URL, for example https://collector:4317",
			endpoint,
		)
	}
	return nil
}
