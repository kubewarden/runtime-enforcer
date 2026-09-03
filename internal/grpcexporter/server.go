package grpcexporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"time"

	"github.com/kubewarden/runtime-enforcer/internal/resolver"
	"github.com/kubewarden/runtime-enforcer/internal/tlsutil"
	"github.com/kubewarden/runtime-enforcer/internal/violationbuf"
	pb "github.com/kubewarden/runtime-enforcer/proto/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const gracefulGRPCTimeout = 5 * time.Second

type Config struct {
	MTLSEnabled bool
	CertDirPath string
	Port        int
}

type Server struct {
	logger          *slog.Logger
	resolver        *resolver.Resolver
	violationBuffer *violationbuf.Buffer
	conf            *Config
}

func (s *Server) getConnCredentials() grpc.ServerOption {
	if !s.conf.MTLSEnabled {
		return grpc.EmptyServerOption{}
	}

	caCertPath := filepath.Join(s.conf.CertDirPath, tlsutil.CAFile)
	tlsCertPath := filepath.Join(s.conf.CertDirPath, tlsutil.CertFile)
	tlsKeyPath := filepath.Join(s.conf.CertDirPath, tlsutil.KeyFile)

	tlsConfig := &tls.Config{
		// gosec: wants the version specified also here
		MinVersion: tls.VersionTLS13,

		// GetConfigForClient called for each handshake, in this way we can handle certificate rotation.
		// in the future we could add a cache to avoid reading files on each handshake but only when the file
		// is updated in the filesystem.
		GetConfigForClient: func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			// Get CA certificate
			certPool, err := tlsutil.LoadCACertPool(caCertPath)
			if err != nil {
				s.logger.Error("mTLS handshake: failed to load CA", "path", caCertPath, "error", err)
				return nil, err
			}

			// Get server certificate
			cert, err := tlsutil.LoadKeyPair(tlsCertPath, tlsKeyPath)
			if err != nil {
				s.logger.Error("mTLS handshake: failed to load key pair", "error", err)
				return nil, err
			}

			// Return a new config for the connection
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    certPool,
				MinVersion:   tls.VersionTLS13,
			}, nil
		},
	}
	return grpc.Creds(credentials.NewTLS(tlsConfig))
}

func New(
	logger *slog.Logger,
	conf *Config,
	resolver *resolver.Resolver,
	violationBuffer *violationbuf.Buffer,
) (*Server, error) {
	if conf.MTLSEnabled {
		// Check that the certificate path is valid before starting the server
		if err := tlsutil.ValidateCertDir(conf.CertDirPath); err != nil {
			return nil, fmt.Errorf("invalid certificate directory: %w", err)
		}
	}
	return &Server{
		logger:          logger.With("component", "grpc_exporter"),
		conf:            conf,
		resolver:        resolver,
		violationBuffer: violationBuffer,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	defer func() {
		s.logger.InfoContext(ctx, "grpcexporter has stopped")
	}()
	lc := net.ListenConfig{}
	addr := fmt.Sprintf(":%d", s.conf.Port)
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	grpcServer := grpc.NewServer(s.getConnCredentials())
	pb.RegisterAgentObserverServer(grpcServer, newAgentObserver(s.logger, s.resolver, s.violationBuffer))
	s.logger.InfoContext(ctx, "Starting gRPC exporter", "addr", addr, "mTLS", s.conf.MTLSEnabled)

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- grpcServer.Serve(listener)
	}()

	select {
	case err = <-serveErrCh:
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil

	case <-ctx.Done():
		done := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(done)
		}()

		select {
		case <-done:
			// graceful stop completed
		case <-time.After(gracefulGRPCTimeout):
			s.logger.WarnContext(ctx, "GracefulStop timed out; forcing Stop()", "timeout", gracefulGRPCTimeout.String())
			grpcServer.Stop()
		}

		// wait for Serve to return (usually immediate after Stop/GracefulStop)
		err = <-serveErrCh
		if err != nil {
			return fmt.Errorf("gRPC server.Serve error: %w", err)
		}
		return nil
	}
}
