package violationbuf_test

import (
	"fmt"
	"testing"

	"github.com/kubewarden/runtime-enforcer/internal/violationbuf"
	"github.com/stretchr/testify/require"
)

func TestBufferRecordAndDrain(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationRecord{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 1)
	require.Equal(t, "pol1", records[0].PolicyName)
	require.Equal(t, "ns1", records[0].Namespace)

	// After drain, buffer should be empty.
	records = buf.Drain()
	require.Empty(t, records)
}

func TestBufferOverwritesOldest(t *testing.T) {
	buf := violationbuf.NewBuffer()

	// Fill the buffer to capacity.
	for i := range violationbuf.MaxBufferEntries {
		dropped := buf.Record(violationbuf.ViolationRecord{
			PolicyName:    fmt.Sprintf("pol-%d", i),
			Namespace:     "ns1",
			PodName:       "pod1",
			ContainerName: "ctr1",
			ExePath:       "/bin/sh",
			NodeName:      "node1",
			Action:        "monitor",
		})
		require.False(t, dropped, "should not drop while filling buffer")
	}

	// Add one more — should overwrite the oldest (pol-0).
	dropped := buf.Record(violationbuf.ViolationRecord{
		PolicyName:    "pol-overflow",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})
	require.True(t, dropped, "should report a drop when buffer overflows")

	records := buf.Drain()
	require.Len(t, records, violationbuf.MaxBufferEntries)

	// Newest should be pol-overflow (first in newest-to-oldest order).
	require.Equal(t, "pol-overflow", records[0].PolicyName)
	// Oldest should now be pol-1 (pol-0 was overwritten).
	require.Equal(t, "pol-1", records[len(records)-1].PolicyName)
}

func TestBufferDifferentKeys(t *testing.T) {
	buf := violationbuf.NewBuffer()

	buf.Record(violationbuf.ViolationRecord{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod1",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	buf.Record(violationbuf.ViolationRecord{
		PolicyName:    "pol1",
		Namespace:     "ns1",
		PodName:       "pod2",
		ContainerName: "ctr1",
		ExePath:       "/bin/sh",
		NodeName:      "node1",
		Action:        "monitor",
	})

	records := buf.Drain()
	require.Len(t, records, 2)
}

func TestBufferDrainReverseChronologicalOrder(t *testing.T) {
	buf := violationbuf.NewBuffer()

	for i := range 5 {
		buf.Record(violationbuf.ViolationRecord{
			PolicyName:    fmt.Sprintf("pol-%d", i),
			Namespace:     "ns1",
			PodName:       "pod1",
			ContainerName: "ctr1",
			ExePath:       "/bin/sh",
			NodeName:      "node1",
			Action:        "monitor",
		})
	}

	records := buf.Drain()
	require.Len(t, records, 5)
	for i, rec := range records {
		require.Equal(t, fmt.Sprintf("pol-%d", 4-i), rec.PolicyName)
	}
}

func TestBufferDrainChronologicalOrderAfterOverflow(t *testing.T) {
	buf := violationbuf.NewBuffer()

	totalRecords := violationbuf.MaxBufferEntries + 50

	for i := range totalRecords {
		buf.Record(violationbuf.ViolationRecord{
			PolicyName:    fmt.Sprintf("pol-%d", i),
			Namespace:     "ns1",
			PodName:       "pod1",
			ContainerName: "ctr1",
			ExePath:       "/bin/sh",
			NodeName:      "node1",
			Action:        "monitor",
		})
	}

	records := buf.Drain()
	require.Len(t, records, violationbuf.MaxBufferEntries)

	// The oldest 50 entries (pol-0 through pol-49) were overwritten.
	// Records should be in reverse chronological order: pol-(totalRecords-1), ..., pol-50.
	for i, rec := range records {
		expected := fmt.Sprintf("pol-%d", totalRecords-1-i)
		require.Equal(
			t,
			expected,
			rec.PolicyName,
			"record at index %d should be %s, got %s",
			i,
			expected,
			rec.PolicyName,
		)
	}

	// Timestamps should be monotonically non-increasing (newest first).
	for i := 1; i < len(records); i++ {
		require.False(t, records[i].Timestamp.After(records[i-1].Timestamp),
			"record %d timestamp %v should not be after record %d timestamp %v",
			i, records[i].Timestamp, i-1, records[i-1].Timestamp)
	}
}
