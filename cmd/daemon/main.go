package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/neuvector/runtime-enforcer/internal/bpf"
	"github.com/neuvector/runtime-enforcer/internal/eventhandler"
	"github.com/neuvector/runtime-enforcer/internal/eventscraper"
	"github.com/neuvector/runtime-enforcer/internal/policygenerator"
	"github.com/neuvector/runtime-enforcer/internal/resolver"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	securityv1alpha1 "github.com/neuvector/runtime-enforcer/api/v1alpha1"
	"github.com/neuvector/runtime-enforcer/internal/traces"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/node/v1alpha1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	cmCache "sigs.k8s.io/controller-runtime/pkg/cache"

	"log/slog"
)

type Config struct {
	enableTracing     bool
	enableOtelSidecar bool
	enableLearning    bool
	nriSocketPath     string
	nriPluginIdx      string
}

// +kubebuilder:rbac:groups=security.rancher.io,resources=workloadpolicies,verbs=get;list;watch
// used by the resolver
// +kubebuilder:rbac:groups="",resources=pods;nodes,verbs=get;list;watch

func newControllerManager() (manager.Manager, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(securityv1alpha1.AddToScheme(scheme))
	cacheOptions := cmCache.Options{
		ByObject: map[client.Object]cmCache.ByObject{
			&corev1.Pod{}: {
				Field: fields.OneTermEqualSelector("spec.nodeName", os.Getenv("NODE_NAME")),
			},
			// todo!: not clear if we need to watch these nodes
			&corev1.Node{}: {
				Field: fields.SelectorFromSet(fields.Set{"metadata.name": os.Getenv("NODE_NAME")}),
			},
		},
	}
	controllerOptions := ctrl.Options{Scheme: scheme, Cache: cacheOptions}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), controllerOptions)
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %w", err)
	}
	return mgr, nil
}

func startDaemon(ctx context.Context, logger *slog.Logger, config Config) error {
	var err error

	//////////////////////
	// Create controller manager
	//////////////////////
	ctrlMgr, err := newControllerManager()
	if err != nil {
		return fmt.Errorf("cannot create manager: %w", err)
	}

	//////////////////////
	// Create BPF manager
	//////////////////////
	bpfManager, err := bpf.NewManager(logger, config.enableLearning, ebpf.LogLevelBranch)
	if err != nil {
		return fmt.Errorf("cannot create BPF manager: %w", err)
	}
	if err = ctrlMgr.Add(bpfManager); err != nil {
		return fmt.Errorf("failed to add BPF manager to controller manager: %w", err)
	}

	//////////////////////
	// Create Learning Reconciler if learning is enabled
	//////////////////////
	// Initialize with a panic function, replaced when learning is enabled
	enqueueFunc := func(_ eventscraper.KubeProcessInfo) {
		panic("enqueue function should be never called when learning is disabled")
	}

	if config.enableLearning {
		learningReconciler := eventhandler.NewLearningReconciler(ctrlMgr.GetClient(), ctrlMgr.GetScheme())
		if err = learningReconciler.SetupWithManager(ctrlMgr); err != nil {
			return fmt.Errorf("unable to create learning reconciler: %w", err)
		}
		enqueueFunc = learningReconciler.EnqueueEvent
		logger.InfoContext(ctx, "learning mode is enabled")
	} else {
		logger.InfoContext(ctx, "learning mode is disabled")
	}

	//////////////////////
	// Create an informer for pods
	//////////////////////
	podInformer, err := ctrlMgr.GetCache().GetInformer(ctx, &corev1.Pod{})
	if err != nil {
		return fmt.Errorf("cannot get pod informer: %w", err)
	}
	// Add some indexes to the pod informer
	// todo!: understand when we use them
	err = podInformer.AddIndexers(cache.Indexers{
		resolver.ContainerIdx: resolver.ContainerIndexFunc,
		resolver.PodIdx:       resolver.PodIndexFunc,
	})
	if err != nil {
		return fmt.Errorf("cannot add indexers to pod informer: %w", err)
	}

	//////////////////////
	// Create the resolver
	//////////////////////
	resolver, err := resolver.NewResolver(
		ctx,
		logger,
		podInformer,
		bpfManager.GetCgroupTrackerUpdateFunc(),
		bpfManager.GetCgroupPolicyUpdateFunc(),
		config.nriSocketPath,
		config.nriPluginIdx,
	)
	if err != nil {
		return fmt.Errorf("failed to create resolver: %w", err)
	}

	//////////////////////
	// Create the scraper
	//////////////////////
	evtScraper := eventscraper.NewEventScraper(
		bpfManager.GetLearningChannel(),
		bpfManager.GetMonitoringChannel(),
		logger,
		resolver,
		enqueueFunc,
	)
	if err = ctrlMgr.Add(evtScraper); err != nil {
		return fmt.Errorf("failed to add event scraper to controller manager: %w", err)
	}

	//////////////////////
	// Setup Policy Generator with the workload informer
	//////////////////////
	workloadPolicyInformer, err := ctrlMgr.GetCache().GetInformer(ctx, &securityv1alpha1.WorkloadPolicy{})
	if err != nil {
		return fmt.Errorf("cannot get workload policy informer: %w", err)
	}
	policygenerator.SetupPolicyGenerator(
		logger,
		workloadPolicyInformer,
		resolver,
		bpfManager.GetPolicyValuesUpdateFunc(),
		bpfManager.GetPolicyModeUpdateFunc(),
	)

	logger.InfoContext(ctx, "starting manager")
	if err = ctrlMgr.Start(ctx); err != nil {
		logger.ErrorContext(ctx, "failed to start manager", "error", err)
	}

	return nil
}

func main() {
	var err error
	var config Config

	var traceShutdown func(context.Context) error

	ctx := ctrl.SetupSignalHandler()

	opts := zap.Options{
		Development: false,
	}
	opts.BindFlags(flag.CommandLine)

	flag.BoolVar(&config.enableTracing, "enable-tracing", false, "Enable tracing collection")
	flag.BoolVar(&config.enableOtelSidecar, "enable-otel-sidecar", false, "Enable OpenTelemetry sidecar")
	flag.BoolVar(&config.enableLearning, "enable-learning", false, "Enable learning mode")
	flag.StringVar(&config.nriSocketPath, "nri-socket-path", "/var/run/nri/nri.sock", "NRI socket path")
	flag.StringVar(&config.nriPluginIdx, "nri-plugin-index", "00", "NRI plugin index")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})).With("component", "daemon")
	slog.SetDefault(logger)

	if config.enableTracing {
		// Start otel traces
		traceShutdown, err = traces.Init()
		if err != nil {
			logger.ErrorContext(ctx, "failed to initiate open telemetry trace", "error", err)
			os.Exit(1)
		}
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// This function blocks if everything is alright.
	if err = startDaemon(ctx, logger, config); err != nil {
		logger.ErrorContext(ctx, "failed to start daemon", "error", err)
		os.Exit(1)
	}

	if traceShutdown != nil {
		if err = traceShutdown(ctx); err != nil {
			logger.ErrorContext(ctx, "failed to shutdown telemetry trace", "error", err)
		}
	}
}
