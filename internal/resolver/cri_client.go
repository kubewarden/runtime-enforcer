package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/neuvector/runtime-enforcer/internal/cgroups"
	"github.com/tidwall/gjson"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var (
	defaultEndpoints = []string{
		"unix:///run/containerd/containerd.sock",
		"unix:///run/crio/crio.sock",
		"unix:///var/run/cri-dockerd.sock",
	}
	errNotUnix = errors.New("only unix endpoints are supported")
)

// The resolver should try to open a new client if the previous one failed.
type criResolver struct {
	ctx      context.Context
	client   criapi.RuntimeServiceClient
	logger   *slog.Logger
	endpoint string
}

func newCRIResolver(ctx context.Context, logger *slog.Logger) (*criResolver, error) {
	criClient := &criResolver{
		ctx:    ctx,
		logger: logger.With("component", "cri-client"),
	}

	// We try to create the client here so that we can fail fast if no endpoint is reachable
	var err error
	if os.Getenv("CUSTOM_CRI_SOCKET_PATH") != "" {
		criClient.endpoint = os.Getenv("CUSTOM_CRI_SOCKET_PATH")
		criClient.endpoint = "unix://" + criClient.endpoint
		criClient.logger.Info("using custom CRI socket path", "path", criClient.endpoint)
		criClient.client, err = newClientTry(ctx, criClient.endpoint)
		if err != nil {
			return nil, err
		}
		return criClient, nil
	}

	for _, ep := range defaultEndpoints {
		criClient.endpoint = ep
		criClient.client, err = newClientTry(ctx, criClient.endpoint)
		if err == nil {
			return criClient, nil
		}
		criClient.logger.Error("cannot create CRI client", "endpoint", criClient.endpoint, "error", err)
	}
	return nil, err
}

func newClientTry(ctx context.Context, endpoint string) (criapi.RuntimeServiceClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "unix" {
		return nil, errNotUnix
	}

	conn, err := grpc.NewClient(endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}

	rtcli := criapi.NewRuntimeServiceClient(conn)
	if _, err := rtcli.Version(context.Background(), &criapi.VersionRequest{}); err != nil {
		return nil, fmt.Errorf("validate CRI v1 runtime API for endpoint %q: %w", endpoint, err)
	}
	return rtcli, nil
}

// taken from github.com/opencontainers/runc/libcontainer/cgroups/systemd
// which does not work due to a ebpf incomaptibility:
// # github.com/opencontainers/runc/libcontainer/cgroups/ebpf
// vendor/github.com/opencontainers/runc/libcontainer/cgroups/ebpf/ebpf_linux.go:190:3: unknown field Replace in struct literal of type link.RawAttachProgramOptions
//
// systemd represents slice hierarchy using `-`, so we need to follow suit when
// generating the path of slice. Essentially, test-a-b.slice becomes
// /test.slice/test-a.slice/test-a-b.slice.
func systemdExpandSlice(slice string) (string, error) {
	suffix := ".slice"
	// Name has to end with ".slice", but can't be just ".slice".
	if len(slice) < len(suffix) || !strings.HasSuffix(slice, suffix) {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	// Path-separators are not allowed.
	if strings.Contains(slice, "/") {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	var path, prefix string
	sliceName := strings.TrimSuffix(slice, suffix)
	// if input was -.slice, we should just return root now
	if sliceName == "-" {
		return "/", nil
	}
	var pathSb116 strings.Builder
	var prefixSb116 strings.Builder
	for _, component := range strings.Split(sliceName, "-") {
		// test--a.slice isn't permitted, nor is -test.slice.
		if component == "" {
			return "", fmt.Errorf("invalid slice name: %s", slice)
		}

		// Append the component to the path and to the prefix.
		pathSb116.WriteString("/" + prefix + component + suffix)
		prefixSb116.WriteString(component + "-")
	}
	path += pathSb116.String()
	prefix += prefixSb116.String()
	return path, nil
}

func ParseCgroupsPath(cgroupPath string) (string, error) {
	if strings.Contains(cgroupPath, "/") {
		return cgroupPath, nil
	}

	// There are some cases where CgroupsPath  is specified as "slice:prefix:name"
	// From runc --help
	//   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name"
	//                       for e.g. "system.slice:runc:434234"
	//
	// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/specconv/spec_linux.go#L655-L663
	parts := strings.Split(cgroupPath, ":")
	if len(parts) == 3 {
		var err error
		slice, scope, name := parts[0], parts[1], parts[2]
		slice, err = systemdExpandSlice(slice)
		if err != nil {
			return "", fmt.Errorf("failed to parse cgroup path: %s (%s does not seem to be a slice)", cgroupPath, slice)
		}
		// https://github.com/opencontainers/runc/blob/5cf9bb229feed19a767cbfdf9702f6487341e29e/libcontainer/cgroups/systemd/common.go#L95-L101
		if !strings.HasSuffix(name, ".slice") {
			name = scope + "-" + name + ".scope"
		}
		return filepath.Join(slice, name), nil
	}

	return "", fmt.Errorf("unknown cgroup path: %s", cgroupPath)
}

func (c *criResolver) getCgroupPath(containerID string) (string, error) {
	req := criapi.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}
	// todo!: we need to handle the case in which we need to recreate the client
	res, err := c.client.ContainerStatus(c.ctx, &req)
	if err != nil {
		return "", err
	}

	info := res.GetInfo()
	if info == nil {
		return "", errors.New("no container info")
	}

	var path, json string
	if infoJson, ok := info["info"]; ok {
		json = infoJson
		path = "runtimeSpec.linux.cgroupsPath"
	} else {
		return "", errors.New("could not find info")
	}

	ret := gjson.Get(json, path).String()
	if ret == "" {
		return "", errors.New("failed to find cgroupsPath in json")
	}

	return ParseCgroupsPath(ret)
}

func (c *criResolver) resolverCgroupID(containerID string) (uint64, error) {
	cgPath, err := c.getCgroupPath(containerID)
	if err != nil {
		return 0, err
	}

	cgRoot, err := cgroups.HostCgroupRoot()
	if err != nil {
		return 0, err
	}

	var getCgroupID func(string) (uint64, error) = cgroups.GetCgroupIdFromPath

	path := filepath.Join(cgRoot, cgPath)
	cgID, err := getCgroupID(path)
	if err != nil {
		return 0, err
	}
	return cgID, nil
}
