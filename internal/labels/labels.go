package labels

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Labels map[string]string

type operator int

const (
	opExists = iota
	opDoesNotExist
	opIn
	opNotIn
)

const (
	K8sPodNamespace = "k8s:io.kubernetes.pod.namespace"
)

type selectorOp struct {
	key      string
	operator operator
	values   []string
}

func (s *selectorOp) hasValue(val string) bool {
	for i := range s.values {
		if val == s.values[i] {
			return true
		}
	}
	return false
}

func (s *selectorOp) match(labels Labels) bool {
	val, exists := labels[s.key]
	switch s.operator {
	case opExists:
		return exists
	case opDoesNotExist:
		return !exists
	case opIn:
		return exists && s.hasValue(val)
	case opNotIn:
		return !exists || !s.hasValue(val)
	default:
		return false
	}
}

type Selector []selectorOp

func (s Selector) Match(labels Labels) bool {
	for i := range s {
		if !s[i].match(labels) {
			return false
		}
	}

	return true
}

func SelectorFromLabelSelector(ls *metav1.LabelSelector) (Selector, error) {
	if ls == nil {
		return []selectorOp{}, nil
	}
	ret := make([]selectorOp, 0, len(ls.MatchLabels)+len(ls.MatchExpressions))
	for key, val := range ls.MatchLabels {
		ret = append(ret, selectorOp{
			key:      key,
			operator: opIn,
			values:   []string{val},
		})
	}
	for _, exp := range ls.MatchExpressions {
		var op operator
		switch exp.Operator {
		case metav1.LabelSelectorOpIn:
			op = opIn
		case metav1.LabelSelectorOpNotIn:
			op = opNotIn
		case metav1.LabelSelectorOpExists:
			op = opExists
		case metav1.LabelSelectorOpDoesNotExist:
			op = opDoesNotExist
		default:
			return nil, fmt.Errorf("unknown operator: '%s'", exp.Operator)
		}

		ret = append(ret, selectorOp{
			key:      exp.Key,
			operator: op,
			values:   exp.Values,
		})
	}

	return ret, nil
}

// Cmp checks if the labels are different. Returns true if they are.
func (l Labels) Cmp(a Labels) bool {
	if len(l) != len(a) {
		return true
	}

	for lk, lv := range l {
		av, ok := a[lk]
		if !ok || lv != av {
			return true
		}
	}

	return false
}
