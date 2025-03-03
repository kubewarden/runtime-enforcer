package controller_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
)

// ConflictFakeClient is a simple fake client designed to test controller error handling:
// - Get() will always return cached object.
// - Update() will fail once with Conflict error.
// - Other API will go through client.Client.
type ConflictFakeClient struct {
	client.Client
}

func (p ConflictFakeClient) Update(
	ctx context.Context,
	obj client.Object,
	opts ...client.UpdateOption,
) error {
	if obj.GetUID() == "" {
		obj.SetUID("12345")
		p.Client.Update(ctx, obj, opts...)
		return k8sErrors.NewConflict(schema.GroupResource{}, obj.GetName(), errors.New("error"))
	}
	return p.Client.Update(ctx, obj, opts...)
}

func TestConflictFakeClient(t *testing.T) {
	var err error
	sts := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "statefulset",
			Namespace: "default",
		},
		Spec: appsv1.StatefulSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "statefulset",
				},
			},
		},
		Status: appsv1.StatefulSetStatus{},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(sts).Build()

	conflictClient := ConflictFakeClient{
		Client: fakeClient,
	}

	err = conflictClient.Update(t.Context(), sts)
	require.Error(t, err)

	err = conflictClient.Update(t.Context(), sts)
	require.NoError(t, err)
}
