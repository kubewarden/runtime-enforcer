package defaults

const (
	// PolicyProxyGRPCAddressEnvKey is the name of the environment variable
	// used to override the gRPC address.
	PolicyProxyGRPCAddressEnvKey = "POLICY_PROXY_GRPC_ADDRESS"
	// WPSControllerUpdateIntervalKey is the name of the environment variable
	// used to override the update interval for the WPS controller.
	WPSControllerUpdateIntervalKey = "WPS_CONTROLLER_UPDATE_INTERVAL"
	// WPSControllerDaemonLabelSelector is the name of the environment variable
	// used to override the label selector used to get daemon pods.
	WPSControllerDaemonLabelSelector = "WPS_CONTROLLER_DAEMON_LABEL_SELECTOR"
	// WPSControllerDaemonNamespace is the name of the environment variable
	// used to override the namespace used to get daemon pods.
	WPSControllerDaemonNamespace = "WPS_CONTROLLER_DAEMON_NAMESPACE"
)
