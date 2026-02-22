package trace

import (
	"sort"
	"strings"
	"time"
)

// SortLineageTraces orders traces using lineage checkpoint metadata when present,
// then falls back to deterministic timestamp/id ordering.
func SortLineageTraces(items []*Trace) {
	if len(items) < 2 {
		return
	}

	nodes := make([]lineageSortNode, len(items))
	checkpointIndex := make(map[string]int, len(items))
	children := make([][]int, len(items))

	for i, item := range items {
		node := lineageSortNode{
			index:     i,
			item:      item,
			traceID:   lineageTraceID(item),
			orderTime: OrderTime(item),
		}
		if item != nil {
			payload := DecodeMetadataMap(item.Metadata)
			node.checkpointID = strings.TrimSpace(MetadataString(payload, "lineage_checkpoint_id"))
			if node.checkpointID == "" {
				node.checkpointID = node.traceID
			}
			node.parentCheckpointID = strings.TrimSpace(MetadataString(payload, "lineage_parent_checkpoint_id"))
			if seq, ok := MetadataInt64(payload, "lineage_checkpoint_seq"); ok && seq > 0 {
				node.resolvedSeq = seq
				node.hasResolvedSeq = true
			}
		}
		nodes[i] = node
		if node.checkpointID != "" {
			if _, exists := checkpointIndex[node.checkpointID]; !exists {
				checkpointIndex[node.checkpointID] = i
			}
		}
	}

	for i := range nodes {
		parentID := nodes[i].parentCheckpointID
		if parentID == "" {
			continue
		}
		parentIdx, ok := checkpointIndex[parentID]
		if !ok || parentIdx == i {
			continue
		}
		nodes[i].indegree++
		children[parentIdx] = append(children[parentIdx], i)
	}

	resolveLineageCheckpointSeq(nodes, checkpointIndex, children)

	order := make([]int, 0, len(nodes))
	processed := make([]bool, len(nodes))
	candidates := make([]int, 0, len(nodes))
	for i := range nodes {
		if nodes[i].indegree == 0 {
			candidates = append(candidates, i)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return lineageNodeLess(nodes, candidates[i], candidates[j])
	})

	for len(candidates) > 0 {
		idx := candidates[0]
		candidates = candidates[1:]
		if processed[idx] {
			continue
		}
		processed[idx] = true
		order = append(order, idx)

		for _, childIdx := range children[idx] {
			nodes[childIdx].indegree--
			if nodes[childIdx].indegree == 0 {
				candidates = append(candidates, childIdx)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			return lineageNodeLess(nodes, candidates[i], candidates[j])
		})
	}

	if len(order) < len(nodes) {
		remainder := make([]int, 0, len(nodes)-len(order))
		for i := range nodes {
			if !processed[i] {
				remainder = append(remainder, i)
			}
		}
		sort.Slice(remainder, func(i, j int) bool {
			return lineageNodeLess(nodes, remainder[i], remainder[j])
		})
		order = append(order, remainder...)
	}

	for i, idx := range order {
		items[i] = nodes[idx].item
	}
}

type lineageSortNode struct {
	index              int
	item               *Trace
	traceID            string
	orderTime          time.Time
	checkpointID       string
	parentCheckpointID string
	resolvedSeq        int64
	hasResolvedSeq     bool
	indegree           int
}

func resolveLineageCheckpointSeq(nodes []lineageSortNode, checkpointIndex map[string]int, children [][]int) {
	if len(nodes) == 0 {
		return
	}

	maxPasses := len(nodes) * 2
	for pass := 0; pass < maxPasses; pass++ {
		progress := false

		// Infer from parent when parent sequence is known.
		for i := range nodes {
			if nodes[i].hasResolvedSeq {
				continue
			}
			parentID := nodes[i].parentCheckpointID
			if parentID == "" {
				continue
			}
			parentIdx, ok := checkpointIndex[parentID]
			if !ok || parentIdx == i || !nodes[parentIdx].hasResolvedSeq {
				continue
			}
			inferred := nodes[parentIdx].resolvedSeq + 1
			if inferred <= 0 {
				continue
			}
			nodes[i].resolvedSeq = inferred
			nodes[i].hasResolvedSeq = true
			progress = true
		}

		// Infer from children when child sequence is known but parent is missing.
		for i := range nodes {
			if nodes[i].hasResolvedSeq {
				continue
			}
			var (
				found    bool
				inferred int64
			)
			for _, childIdx := range children[i] {
				if !nodes[childIdx].hasResolvedSeq {
					continue
				}
				candidate := nodes[childIdx].resolvedSeq - 1
				if candidate <= 0 {
					continue
				}
				if !found || candidate < inferred {
					found = true
					inferred = candidate
				}
			}
			if !found {
				continue
			}
			nodes[i].resolvedSeq = inferred
			nodes[i].hasResolvedSeq = true
			progress = true
		}

		if !progress {
			break
		}
	}
}

func lineageNodeLess(nodes []lineageSortNode, left, right int) bool {
	a := nodes[left]
	b := nodes[right]

	if a.hasResolvedSeq != b.hasResolvedSeq {
		return a.hasResolvedSeq
	}
	if a.hasResolvedSeq && b.hasResolvedSeq && a.resolvedSeq != b.resolvedSeq {
		return a.resolvedSeq < b.resolvedSeq
	}
	if !a.orderTime.Equal(b.orderTime) {
		return a.orderTime.Before(b.orderTime)
	}
	if a.traceID != b.traceID {
		return a.traceID < b.traceID
	}
	return a.index < b.index
}

func lineageTraceID(item *Trace) string {
	if item == nil {
		return ""
	}
	return strings.TrimSpace(item.ID)
}
