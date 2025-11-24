package tetragon

import (
	"fmt"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// TetragonSockPath is the path to the Tetragon gRPC socket.
	TetragonSockPath = "unix:///var/run/tetragon/tetragon.sock"
	// OneShotRequestTimeout is the timeout for one-shot requests to Tetragon.
	OneShotRequestTimeout = 30 * time.Second
)

// Client wraps the gRPC client and connection to Tetragon.
type Client struct {
	Client tetragon.FineGuidanceSensorsClient
	conn   *grpc.ClientConn
}

func NewTetragonClient() (*Client, error) {
	c := &Client{}

	var err error
	c.conn, err = grpc.NewClient(TetragonSockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", TetragonSockPath, err)
	}
	c.Client = tetragon.NewFineGuidanceSensorsClient(c.conn)
	return c, nil
}

// Close releases the underlying gRPC connection and cancels contexts.
func (c *Client) Close() {
	_ = c.conn.Close()
}
