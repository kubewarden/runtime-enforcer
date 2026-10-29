// Package manifest reads streams of Kubernetes objects in YAML or JSON.
package manifest

import (
	"errors"
	"fmt"
	"io"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const decoderBufferSize = 4096

// ForEachObject calls fn for each object of a stream of YAML or JSON
// documents, in order. Empty documents are ignored, and the items of a List
// are passed one by one. The errors of fn are returned with the number of
// the document.
func ForEachObject(r io.Reader, fn func(obj *unstructured.Unstructured) error) error {
	decoder := yaml.NewYAMLOrJSONDecoder(r, decoderBufferSize)
	for doc := 1; ; doc++ {
		obj := &unstructured.Unstructured{}
		err := decoder.Decode(&obj.Object)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("document %d: %w", doc, err)
		}
		if len(obj.Object) == 0 {
			continue
		}

		objects := []*unstructured.Unstructured{obj}
		if obj.IsList() {
			if objects, err = listItems(obj); err != nil {
				return fmt.Errorf("document %d: %w", doc, err)
			}
		}

		for _, o := range objects {
			if err = fn(o); err != nil {
				return fmt.Errorf("document %d: %w", doc, err)
			}
		}
	}
}

func listItems(list *unstructured.Unstructured) ([]*unstructured.Unstructured, error) {
	var items []*unstructured.Unstructured
	err := list.EachListItem(func(o runtime.Object) error {
		u, ok := o.(*unstructured.Unstructured)
		if !ok {
			return fmt.Errorf("unexpected list item type %T", o)
		}
		items = append(items, u)
		return nil
	})
	return items, err
}
