package imagescan

import "io"

// Classify exposes classify to the tests of package imagescan_test.
func Classify(r io.Reader) (Kind, error) {
	return classify(r)
}

// MaxDynamicSize exposes maxDynamicSize to the tests.
const MaxDynamicSize = maxDynamicSize
