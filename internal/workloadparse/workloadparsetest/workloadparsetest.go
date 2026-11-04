// Package workloadparsetest builds Kubernetes manifests from typed objects
// for tests.
package workloadparsetest

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

// WithGVK sets apiVersion and kind of the object from the client-go scheme.
func WithGVK(t *testing.T, obj runtime.Object) runtime.Object {
	t.Helper()

	gvks, _, err := scheme.Scheme.ObjectKinds(obj)
	require.NoError(t, err)
	obj.GetObjectKind().SetGroupVersionKind(gvks[0])
	return obj
}

// Manifest encodes the objects as a multi-document YAML stream.
func Manifest(t *testing.T, objs ...runtime.Object) io.Reader {
	t.Helper()

	var buf bytes.Buffer
	for i, obj := range objs {
		data, err := yaml.Marshal(WithGVK(t, obj))
		require.NoError(t, err)
		if i > 0 {
			buf.WriteString("---\n")
		}
		buf.Write(data)
	}
	return &buf
}

// WriteFile writes the manifest of the objects to a new file and returns the
// path of the file. Without objects, the file is empty.
func WriteFile(t *testing.T, objs ...runtime.Object) string {
	t.Helper()

	data, err := io.ReadAll(Manifest(t, objs...))
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "manifest.yaml")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}
