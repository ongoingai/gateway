package trace

import "time"

type Trace struct {
	ID                 string
	TraceGroupID       string
	OrgID              string
	WorkspaceID        string
	Timestamp          time.Time
	Provider           string
	Model              string
	RequestMethod      string
	RequestPath        string
	RequestHeaders     string
	RequestBody        string
	ResponseStatus     int
	ResponseHeaders    string
	ResponseBody       string
	InputTokens        int
	OutputTokens       int
	TotalTokens        int
	LatencyMS          int64
	TimeToFirstTokenMS int64
	TimeToFirstTokenUS int64
	APIKeyHash         string
	GatewayKeyID       string
	EstimatedCostUSD   float64
	Metadata           string
	CreatedAt          time.Time
}
