// Package proxy provides the core reverse proxy server and request handling.
package proxy

import "github.com/tejaspatil1936/Consensus-Lab/proxyshield/proxyshield-core/internal/reqctx"

// RequestContext is a type alias for reqctx.Context for backward compatibility.
// Middlewares should import reqctx directly to avoid import cycles.
type RequestContext = reqctx.Context

// RateLimitInfo is a type alias for reqctx.RateLimitInfo.
type RateLimitInfo = reqctx.RateLimitInfo
