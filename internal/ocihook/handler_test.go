package ocihook

import (
	"context"
	"encoding/json"
	"net"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	ctrlLog "sigs.k8s.io/controller-runtime/pkg/log"
)

const testHandlerSocketPath = "/opt/oci/oci-handler-test.sock"

func testCtx(t *testing.T) context.Context {
	t.Helper()
	return ctrlLog.IntoContext(context.Background(), logr.Discard())
}

// withPipeConn runs handleConn on the server end of a pipe while fn drives the client end.
// fn must close the client connection when finished.
func withPipeConn(t *testing.T, h *Handler, fn func(t *testing.T, client net.Conn)) {
	t.Helper()
	ctx := testCtx(t)
	server, client := net.Pipe()

	go func() {
		h.handleConn(ctx, server)
	}()

	fn(t, client)
}

func TestHandler_handleConn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		rawBytes         []byte // if non-nil, written instead of JSON-encoding req
		req              HookRequest
		trackerErr       error
		wantTrackerCalls int32
		wantOK           bool
		wantErrSubstring string // required when wantOK is false
		wantErrExtra     string // optional second substring on response error
		wantID           uint64
		wantPath         string
	}{
		{
			name: "success",
			req: HookRequest{
				CgroupID:   1,
				CgroupPath: "/cgroup/path1",
			},
			wantTrackerCalls: 1,
			wantOK:           true,
			wantID:           1,
			wantPath:         "/cgroup/path1",
		},
		{
			name:             "decode error",
			rawBytes:         []byte("not-json\n"),
			wantTrackerCalls: 0,
			wantOK:           false,
			wantErrSubstring: "decode request",
		},
		{
			name: "invalid cgroup id",
			req: HookRequest{
				CgroupID:   0,
				CgroupPath: "/cgroup/path0",
			},
			wantTrackerCalls: 0,
			wantOK:           false,
			wantErrSubstring: "invalid cgroupId or cgroupPath",
		},
		{
			name: "empty cgroup path",
			req: HookRequest{
				CgroupID:   2,
				CgroupPath: "",
			},
			wantTrackerCalls: 0,
			wantOK:           false,
			wantErrSubstring: "invalid cgroupId or cgroupPath",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32
			var gotID uint64
			var gotPath string

			h := NewHandler(testHandlerSocketPath, func(id uint64, path string) error {
				calls.Add(1)
				gotID = id
				gotPath = path
				return tc.trackerErr
			})

			withPipeConn(t, h, func(t *testing.T, client net.Conn) {
				defer client.Close()
				if tc.rawBytes != nil {
					_, err := client.Write(tc.rawBytes)
					require.NoError(t, err)
				} else {
					require.NoError(t, json.NewEncoder(client).Encode(tc.req))
				}

				var resp HookResponse
				require.NoError(t, json.NewDecoder(client).Decode(&resp))
				require.Equal(t, tc.wantOK, resp.OK, "response=%+v", resp)
				if tc.wantErrSubstring != "" {
					require.Contains(t, resp.Error, tc.wantErrSubstring)
				}
				if tc.wantErrExtra != "" {
					require.Contains(t, resp.Error, tc.wantErrExtra)
				}
			})

			require.Equal(t, tc.wantTrackerCalls, calls.Load())
			if tc.wantOK {
				require.Equal(t, tc.wantID, gotID)
				require.Equal(t, tc.wantPath, gotPath)
			}
		})
	}
}
