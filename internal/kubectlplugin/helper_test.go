package kubectlplugin

import (
	"net/http"
	"sync"
	"testing"

	securityv1alpha1 "github.com/kubewarden/runtime-enforcer/api/v1alpha1"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/cli-runtime/pkg/resource"
	"k8s.io/client-go/rest/fake"
	cmdtesting "k8s.io/kubectl/pkg/cmd/testing"
	"k8s.io/kubectl/pkg/scheme"
)

var schemeOnce sync.Once //nolint:gochecknoglobals // we want to share the scheme across tests.

// setupTestFactory creates a test factory with a fake REST client that returns the provided object
// as the response body for any request.
// It's caller's responsibility to call tf.Cleanup() when the test is done to clean up the factory.
func setupTestFactory(t *testing.T, obj runtime.Object) (*cmdtesting.TestFactory, genericiooptions.IOStreams) {
	t.Helper()

	schemeOnce.Do(func() {
		// Add all known types to the scheme, so that the fake REST client can properly encode them in the response.
		// This has to be done in a thread-safe way, so that multiple tests can call setupTestFactory concurrently.
		require.NoError(t, securityv1alpha1.AddToScheme(scheme.Scheme))
	})

	tf := cmdtesting.NewTestFactory().WithNamespace("test")

	streams, _, _, _ := genericiooptions.NewTestIOStreams()
	codec := scheme.Codecs.LegacyCodec(scheme.Scheme.PrioritizedVersionsAllGroups()...)

	// The fake REST client will return the object only one time.
	tf.UnstructuredClient = &fake.RESTClient{
		NegotiatedSerializer: resource.UnstructuredPlusDefaultContentConfig().NegotiatedSerializer,
		Resp: &http.Response{
			StatusCode: http.StatusOK,
			Header:     cmdtesting.DefaultHeader(),
			Body:       cmdtesting.ObjBody(codec, obj),
		},
	}

	return tf, streams
}
