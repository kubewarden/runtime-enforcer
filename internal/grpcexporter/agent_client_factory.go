package grpcexporter

import (
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"strconv"

	"github.com/kubewarden/runtime-enforcer/internal/tlsutil"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// AgentClientFactory is responsible for creating agent clients.
type AgentClientFactory struct {
	port        string
	mTLSEnabled bool
	tlsCertPath string
	tlsKeyPath  string
	caCertPath  string
}

type AgentFactoryConfig struct {
	MTLSEnabled bool
	CertDirPath string
	Port        int
}

func NewAgentClientFactory(conf *AgentFactoryConfig) (*AgentClientFactory, error) {
	if conf.Port == 0 {
		return nil, fmt.Errorf("invalid gRPC port: %d", conf.Port)
	}

	var tlsCertPath string
	var tlsKeyPath string
	var caCertPath string
	if conf.MTLSEnabled {
		if err := tlsutil.ValidateCertDir(conf.CertDirPath); err != nil {
			return nil, fmt.Errorf("invalid certificate directory %q: %w", conf.CertDirPath, err)
		}
		tlsCertPath = filepath.Join(conf.CertDirPath, tlsutil.CertFile)
		tlsKeyPath = filepath.Join(conf.CertDirPath, tlsutil.KeyFile)
		caCertPath = filepath.Join(conf.CertDirPath, tlsutil.CAFile)
	}
	return &AgentClientFactory{
		port:        strconv.Itoa(conf.Port),
		tlsCertPath: tlsCertPath,
		tlsKeyPath:  tlsKeyPath,
		caCertPath:  caCertPath,
		mTLSEnabled: conf.MTLSEnabled,
	}, nil
}

func (f *AgentClientFactory) getConnCredentials(podNamespacedName string) (credentials.TransportCredentials, error) {
	if !f.mTLSEnabled {
		return insecure.NewCredentials(), nil
	}

	// we get them at each new connection so that we manage certificate rotation.
	certPool, err := tlsutil.LoadCACertPool(f.caCertPath)
	if err != nil {
		return nil, err
	}

	clientCert, err := tlsutil.LoadKeyPair(f.tlsCertPath, f.tlsKeyPath)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
		// the service name in the server certificate will be in this form
		ServerName: podNamespacedName,
	}
	return credentials.NewTLS(tlsConfig), nil
}

func (f *AgentClientFactory) NewClient(podIP, podName, podNamespace string) (*AgentClient, error) {
	creds, err := f.getConnCredentials(fmt.Sprintf("%s.%s", podName, podNamespace))
	if err != nil {
		return nil, fmt.Errorf("failed to get connection credentials: %w", err)
	}

	host := net.JoinHostPort(podIP, f.port)
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed host %s: %w", host, err)
	}

	return &AgentClient{
		conn:    conn,
		client:  pb.NewAgentObserverClient(conn),
		timeout: agentClientTimeout, // for now this is a constant
	}, nil
}
