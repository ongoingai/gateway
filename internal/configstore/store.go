package configstore

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

var ErrNotImplemented = errors.New("config store method not implemented")
var ErrNotFound = errors.New("config store record not found")
var ErrConflict = errors.New("config store record conflicts with existing data")

type GatewayKeyFilter struct {
	OrgID       string
	WorkspaceID string
}

type GatewayKey struct {
	ID          string
	Token       string
	TokenHash   string
	OrgID       string
	WorkspaceID string
	Team        string
	Name        string
	Description string
	CreatedBy   string
	LastUsedAt  time.Time
	Role        string
	Permissions []string
	CreatedAt   time.Time
	RevokedAt   time.Time
}

// Organization is the top-level tenant boundary for gateway data.
type Organization struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Workspace is a collaboration boundary within an organization.
type Workspace struct {
	ID        string
	OrgID     string
	Name      string
	CreatedAt time.Time
}

type GatewayKeyStore interface {
	ListGatewayKeys(ctx context.Context, filter GatewayKeyFilter) ([]GatewayKey, error)
	CreateGatewayKey(ctx context.Context, key GatewayKey) (*GatewayKey, error)
	RevokeGatewayKey(ctx context.Context, id string, filter GatewayKeyFilter) error
	RotateGatewayKey(ctx context.Context, id, token string, filter GatewayKeyFilter) (*GatewayKey, error)
	Close() error
}

// ConfigStore is the gateway configuration boundary that backs key resolution,
// gateway key management, and tenant hierarchy lookups.
type ConfigStore interface {
	GatewayKeyStore
	GatewayKeyUsageTracker
	OrgStore

	// GetGatewayKey resolves an active gateway key by token hash.
	GetGatewayKey(ctx context.Context, keyHash string) (*GatewayKey, error)
}

// OrgStore resolves the organization -> workspace hierarchy used by gateway keys.
type OrgStore interface {
	GetOrganization(ctx context.Context, id string) (*Organization, error)
	GetWorkspace(ctx context.Context, id string) (*Workspace, error)
	ListWorkspaces(ctx context.Context, orgID string) ([]Workspace, error)
}

type GatewayKeyUsageTracker interface {
	TouchGatewayKeyLastUsed(ctx context.Context, id string, filter GatewayKeyFilter) error
}

type StaticStore struct {
	keys []GatewayKey
}

var _ ConfigStore = (*StaticStore)(nil)
var _ ConfigStore = (*PostgresStore)(nil)

func NewStaticStore(keys []GatewayKey) *StaticStore {
	copied := make([]GatewayKey, 0, len(keys))
	for _, key := range keys {
		keyCopy := key
		keyCopy.Permissions = append([]string(nil), key.Permissions...)
		copied = append(copied, keyCopy)
	}
	return &StaticStore{keys: copied}
}

func (s *StaticStore) ListGatewayKeys(_ context.Context, filter GatewayKeyFilter) ([]GatewayKey, error) {
	if s == nil || len(s.keys) == 0 {
		return nil, nil
	}
	out := make([]GatewayKey, 0, len(s.keys))
	orgFilter := strings.TrimSpace(filter.OrgID)
	workspaceFilter := strings.TrimSpace(filter.WorkspaceID)
	for _, key := range s.keys {
		if orgFilter != "" && strings.TrimSpace(key.OrgID) != orgFilter {
			continue
		}
		if workspaceFilter != "" && strings.TrimSpace(key.WorkspaceID) != workspaceFilter {
			continue
		}
		keyCopy := key
		keyCopy.Permissions = append([]string(nil), key.Permissions...)
		out = append(out, keyCopy)
	}
	return out, nil
}

func (s *StaticStore) CreateGatewayKey(_ context.Context, _ GatewayKey) (*GatewayKey, error) {
	return nil, ErrNotImplemented
}

func (s *StaticStore) RevokeGatewayKey(_ context.Context, _ string, _ GatewayKeyFilter) error {
	return ErrNotImplemented
}

func (s *StaticStore) RotateGatewayKey(_ context.Context, _ string, _ string, _ GatewayKeyFilter) (*GatewayKey, error) {
	return nil, ErrNotImplemented
}

func (s *StaticStore) Close() error {
	return nil
}

func (s *StaticStore) TouchGatewayKeyLastUsed(_ context.Context, _ string, _ GatewayKeyFilter) error {
	return nil
}

func (s *StaticStore) GetGatewayKey(_ context.Context, keyHash string) (*GatewayKey, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	keyHash = normalizeTokenHash(keyHash)
	if keyHash == "" {
		return nil, ErrNotFound
	}

	for _, key := range s.keys {
		if !key.RevokedAt.IsZero() {
			continue
		}
		candidateHash := normalizeTokenHash(key.TokenHash)
		if candidateHash == "" {
			token := strings.TrimSpace(key.Token)
			if token == "" {
				continue
			}
			candidateHash = hashToken(token)
		}
		if candidateHash != keyHash {
			continue
		}

		item := key
		item.TokenHash = candidateHash
		item.Token = ""
		item.Team = firstNonEmpty(strings.TrimSpace(item.Team), strings.TrimSpace(item.WorkspaceID))
		item.OrgID = nonEmpty(strings.TrimSpace(item.OrgID), "default")
		item.WorkspaceID = nonEmpty(firstNonEmpty(strings.TrimSpace(item.WorkspaceID), strings.TrimSpace(item.Team)), "default")
		item.Permissions = append([]string(nil), item.Permissions...)
		return &item, nil
	}
	return nil, ErrNotFound
}

func (s *StaticStore) GetOrganization(_ context.Context, id string) (*Organization, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}

	orgs, _ := staticHierarchy(s.keys)
	item, ok := orgs[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := item
	return &out, nil
}

func (s *StaticStore) GetWorkspace(_ context.Context, id string) (*Workspace, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, ErrNotFound
	}

	_, workspaces := staticHierarchy(s.keys)
	item, ok := workspaces[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := item
	return &out, nil
}

func (s *StaticStore) ListWorkspaces(_ context.Context, orgID string) ([]Workspace, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, ErrNotFound
	}

	_, workspaces := staticHierarchy(s.keys)
	out := make([]Workspace, 0, len(workspaces))
	for _, item := range workspaces {
		if strings.TrimSpace(item.OrgID) != orgID {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

func staticHierarchy(keys []GatewayKey) (map[string]Organization, map[string]Workspace) {
	orgs := make(map[string]Organization)
	workspaces := make(map[string]Workspace)

	if len(keys) == 0 {
		orgs["default"] = Organization{ID: "default", Name: "Default Organization"}
		workspaces["default"] = Workspace{ID: "default", OrgID: "default", Name: "Default Workspace"}
		return orgs, workspaces
	}

	for _, key := range keys {
		orgID := nonEmpty(strings.TrimSpace(key.OrgID), "default")
		workspaceID := nonEmpty(strings.TrimSpace(key.WorkspaceID), "default")

		if _, exists := orgs[orgID]; !exists {
			orgs[orgID] = Organization{ID: orgID}
		}
		if _, exists := workspaces[workspaceID]; !exists {
			workspaces[workspaceID] = Workspace{
				ID:    workspaceID,
				OrgID: orgID,
			}
		}
	}

	return orgs, workspaces
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
