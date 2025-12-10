package labels_test

import (
	"testing"

	"github.com/neuvector/runtime-enforcer/internal/labels"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type testLabel struct {
	labels      labels.Labels
	expectedRes bool
	namespace   string
}

type testCase struct {
	labelSelector *metav1.LabelSelector
	tests         []testLabel
}

func TestLabels(t *testing.T) {
	testCases := []testCase{
		{
			// empty label selector should match everything
			labelSelector: &metav1.LabelSelector{},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, true, "default"},
				{labels.Labels{}, true, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "app1",
				},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, true, "default"},
				{map[string]string{"app": "app2"}, false, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "In",
					Values:   []string{"app1", "app2"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, true, "default"},
				{map[string]string{"app": "app2"}, true, "default"},
				{map[string]string{"app": "app3"}, false, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "NotIn",
					Values:   []string{"app1", "app2"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, false, "default"},
				{map[string]string{"app": "app2"}, false, "default"},
				{map[string]string{"app": "app3"}, true, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "Exists",
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, true, "default"},
				{map[string]string{"application": "app2"}, false, "default"},
				{map[string]string{"app": "app3"}, true, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "DoesNotExist",
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, false, "default"},
				{map[string]string{"application": "app2"}, true, "default"},
				{map[string]string{"app": "app3"}, false, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "application",
					Operator: "DoesNotExist",
				}},
				MatchLabels: map[string]string{
					"app": "app1",
				},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, true, "default"},
				{map[string]string{"application": "app1"}, false, "default"},
				{map[string]string{"app": "app1", "application": "app1"}, false, "default"},
				{map[string]string{"app": "app1", "pizza": "yes"}, true, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      labels.K8sPodNamespace,
					Operator: "In",
					Values:   []string{"app1"},
				}},
			},
			tests: []testLabel{
				{map[string]string{labels.K8sPodNamespace: "app1"}, true, "app1"},
				{map[string]string{labels.K8sPodNamespace: "test"}, false, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      labels.K8sPodNamespace,
					Operator: "In",
					Values:   []string{"app2", "app1"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, true, "app2"},
				{map[string]string{"app": "app2"}, true, "app1"},
				{map[string]string{"app": "app3"}, false, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      labels.K8sPodNamespace,
					Operator: "NotIn",
					Values:   []string{"app2", "app1"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "app1"}, false, "app2"},
				{map[string]string{"app": "app2"}, false, "app1"},
				{map[string]string{"app": "app3"}, true, "default"},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      labels.K8sPodNamespace,
					Operator: "Exists",
				}},
			},
			tests: []testLabel{
				{map[string]string{labels.K8sPodNamespace: "app1"}, true, "app1"},
				{map[string]string{}, true, ""},
			},
		}, {
			labelSelector: &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "name",
					Operator: "In",
					Values:   []string{"main", "secondary"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"name": "main"}, true, ""},
				{map[string]string{"name": "secondary"}, true, ""},
				{map[string]string{"name": "init"}, false, ""},
			},
		},
	}

	for _, tc := range testCases {
		selector, err := labels.SelectorFromLabelSelector(tc.labelSelector)
		require.NoError(t, err)
		for _, test := range tc.tests {
			if _, ok := test.labels[labels.K8sPodNamespace]; !ok {
				test.labels[labels.K8sPodNamespace] = test.namespace
			}
			res := selector.Match(test.labels)
			if res != test.expectedRes {
				t.Fatalf(
					"label selector:%+v labels:%+v expected:%t got:%t",
					tc.labelSelector,
					test.labels,
					test.expectedRes,
					res,
				)
			}
		}
	}
}

type testCmp struct {
	l1, l2   map[string]string
	expected bool
}

func TestCmp(t *testing.T) {
	cases := []testCmp{
		{l1: map[string]string{}, l2: map[string]string{}, expected: false},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{}, expected: true},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{"label1": "b"}, expected: true},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{"label1": "a"}, expected: false},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{"label2": "a"}, expected: true},
	}

	for _, tc := range cases {
		require.Equal(t, tc.expected, labels.Labels(tc.l1).Cmp(tc.l2), "test: %+v", tc)
		require.Equal(t, tc.expected, labels.Labels(tc.l2).Cmp(tc.l1), "reverse-test: %+v", tc)
	}
}
