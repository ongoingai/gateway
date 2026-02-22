package trace

import (
	"encoding/json"
	"sort"
	"strconv"
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
			orderTime: lineageOrderTime(item),
		}
		if item != nil {
			meta := decodeLineageSortMetadata(item.Metadata)
			node.checkpointID = strings.TrimSpace(meta.CheckpointID)
			if node.checkpointID == "" {
				node.checkpointID = node.traceID
			}
			node.parentCheckpointID = strings.TrimSpace(meta.ParentCheckpointID)
			if meta.CheckpointSeq > 0 {
				node.resolvedSeq = meta.CheckpointSeq
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

type lineageSortMetadata struct {
	CheckpointID       string
	ParentCheckpointID string
	CheckpointSeq      int64
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

func lineageOrderTime(item *Trace) time.Time {
	if item == nil {
		return time.Time{}
	}
	if !item.CreatedAt.IsZero() {
		return item.CreatedAt.UTC()
	}
	return item.Timestamp.UTC()
}

func lineageTraceID(item *Trace) string {
	if item == nil {
		return ""
	}
	return strings.TrimSpace(item.ID)
}

func decodeLineageSortMetadata(raw string) lineageSortMetadata {
	if strings.TrimSpace(raw) == "" {
		return lineageSortMetadata{}
	}
	payload := make(map[string]any)
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return lineageSortMetadata{}
	}

	result := lineageSortMetadata{
		CheckpointID:       lineageSortString(payload, "lineage_checkpoint_id"),
		ParentCheckpointID: lineageSortString(payload, "lineage_parent_checkpoint_id"),
	}
	if seq, ok := lineageSortInt64(payload["lineage_checkpoint_seq"]); ok && seq > 0 {
		result.CheckpointSeq = seq
	}
	return result
}

func lineageSortString(payload map[string]any, key string) string {
	if len(payload) == 0 {
		return ""
	}
	value, ok := payload[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func lineageSortInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case float32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
