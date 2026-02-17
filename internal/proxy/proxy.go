package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/ongoingai/gateway/internal/pathutil"
)

type Route struct {
	Prefix   string
	Upstream string
}

type Router struct {
	routes []Route
}

type HandlerOptions struct {
	Transport http.RoundTripper
}

func NewRouter(routes []Route) *Router {
	normalized := make([]Route, 0, len(routes))
	for _, route := range routes {
		normalized = append(normalized, Route{
			Prefix:   pathutil.NormalizePrefix(route.Prefix),
			Upstream: route.Upstream,
		})
	}
	return &Router{routes: normalized}
}

func NewHandler(routes []Route, logger *slog.Logger, next http.Handler) (http.Handler, error) {
	return NewHandlerWithOptions(routes, logger, next, HandlerOptions{})
}

func NewHandlerWithOptions(routes []Route, logger *slog.Logger, next http.Handler, options HandlerOptions) (http.Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if next == nil {
		next = http.NotFoundHandler()
	}

	router := NewRouter(routes)
	proxies := make(map[string]http.Handler, len(router.routes))
	for _, route := range router.routes {
		handler, err := buildProxyHandler(route, logger, options.Transport)
		if err != nil {
			return nil, err
		}
		proxies[route.Prefix] = handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, ok := router.Match(r.URL.Path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		proxies[route.Prefix].ServeHTTP(w, r)
	}), nil
}

func DefaultRoutes() []Route {
	return []Route{
		{Prefix: "/openai", Upstream: "https://api.openai.com"},
		{Prefix: "/anthropic", Upstream: "https://api.anthropic.com"},
	}
}

func (r *Router) Match(path string) (Route, bool) {
	for _, route := range r.routes {
		if pathutil.HasPathPrefix(path, route.Prefix) {
			return route, true
		}
	}

	return Route{}, false
}

func buildProxyHandler(route Route, logger *slog.Logger, transport http.RoundTripper) (http.Handler, error) {
	target, err := url.Parse(route.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream for %q: %w", route.Prefix, err)
	}
	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("invalid upstream for %q: %q", route.Prefix, route.Upstream)
	}

	prefix := route.Prefix
	proxy := httputil.NewSingleHostReverseProxy(target)
	if transport != nil {
		proxy.Transport = transport
	}
	baseDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.URL.Path = pathutil.StripPathPrefix(req.URL.Path, prefix)
		baseDirector(req)
		req.Host = target.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, req *http.Request, proxyErr error) {
		logger.Error("proxy request failed", "provider_prefix", prefix, "path", req.URL.Path, "error", proxyErr)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
	}

	return proxy, nil
}
