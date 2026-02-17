package providers

import "sort"

type Registry struct {
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) *Registry {
	registry := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, provider := range providers {
		registry.providers[provider.Name()] = provider
	}
	return registry
}

func DefaultRegistry() *Registry {
	return NewRegistry(OpenAIProvider{}, AnthropicProvider{})
}

func (r *Registry) Get(name string) (Provider, bool) {
	provider, ok := r.providers[name]
	return provider, ok
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
