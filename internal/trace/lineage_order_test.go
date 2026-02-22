package trace

import (
	"testing"
	"time"
)

func TestSortLineageTracesOrdersByCheckpointSeqForOutOfOrderWrites(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	items := []*Trace{
		{
			ID:        "trace-step-3",
			CreatedAt: base,
			Timestamp: base,
			Metadata:  `{"lineage_checkpoint_id":"trace-step-3","lineage_checkpoint_seq":3}`,
		},
		{
			ID:        "trace-step-1",
			CreatedAt: base.Add(2 * time.Minute),
			Timestamp: base.Add(2 * time.Minute),
			Metadata:  `{"lineage_checkpoint_id":"trace-step-1","lineage_checkpoint_seq":1}`,
		},
		{
			ID:        "trace-step-2",
			CreatedAt: base.Add(1 * time.Minute),
			Timestamp: base.Add(1 * time.Minute),
			Metadata:  `{"lineage_checkpoint_id":"trace-step-2","lineage_checkpoint_seq":2}`,
		},
	}

	SortLineageTraces(items)

	got := []string{items[0].ID, items[1].ID, items[2].ID}
	want := []string{"trace-step-1", "trace-step-2", "trace-step-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids[%d]=%q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestSortLineageTracesInfersOrderFromPartialLineageMetadata(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 2, 20, 13, 0, 0, 0, time.UTC)
	items := []*Trace{
		{
			ID:        "trace-step-3",
			CreatedAt: base,
			Timestamp: base,
			Metadata:  `{"lineage_checkpoint_id":"trace-step-3","lineage_parent_checkpoint_id":"trace-step-2"}`,
		},
		{
			ID:        "trace-step-2",
			CreatedAt: base.Add(3 * time.Minute),
			Timestamp: base.Add(3 * time.Minute),
			Metadata:  `{"lineage_checkpoint_id":"trace-step-2","lineage_parent_checkpoint_id":"trace-step-1","lineage_checkpoint_seq":2}`,
		},
		{
			ID:        "trace-step-1",
			CreatedAt: base.Add(4 * time.Minute),
			Timestamp: base.Add(4 * time.Minute),
			Metadata:  `{"lineage_checkpoint_id":"trace-step-1"}`,
		},
	}

	SortLineageTraces(items)

	got := []string{items[0].ID, items[1].ID, items[2].ID}
	want := []string{"trace-step-1", "trace-step-2", "trace-step-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids[%d]=%q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}
