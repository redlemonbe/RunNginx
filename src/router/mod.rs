// Request router: Host → ServerBlock, URI → LocationBlock.
// Implements nginx's documented selection algorithm exactly.

use std::sync::Arc;

use crate::config::types::{LocationBlock, LocationPattern, ServerBlock, ServerName};

// ── Server selection ──────────────────────────────────────────────────────────

/// Select the best ServerBlock for a given Host header value and listener address.
/// nginx selection order:
///   1. Exact server_name match
///   2. Wildcard prefix match (*.example.com)
///   3. Wildcard suffix match (.example.com)
///   4. default_server on the matching listen directive
///   5. First server block (implicit default)
pub fn select_server<'a>(servers: &'a [Arc<ServerBlock>], host: &str) -> &'a Arc<ServerBlock> {
    // Strip port from Host header if present.
    let host = host.split(':').next().unwrap_or(host).trim();

    // 1. Exact match
    for srv in servers {
        for name in &srv.server_names {
            if matches!(name, ServerName::Exact(_)) && name.matches(host) {
                return srv;
            }
        }
    }

    // 2. Wildcard *.example.com
    for srv in servers {
        for name in &srv.server_names {
            if matches!(name, ServerName::Wildcard(_)) && name.matches(host) {
                return srv;
            }
        }
    }

    // 3. Suffix .example.com
    for srv in servers {
        for name in &srv.server_names {
            if matches!(name, ServerName::Suffix(_)) && name.matches(host) {
                return srv;
            }
        }
    }

    // 4. CatchAll (_)
    for srv in servers {
        for name in &srv.server_names {
            if matches!(name, ServerName::CatchAll) {
                return srv;
            }
        }
    }

    // 5. First server (implicit default)
    &servers[0]
}

// ── Location selection ────────────────────────────────────────────────────────

/// Select the best LocationBlock for a given request URI path.
/// nginx location priority:
///   1. Exact match (=) — immediate return
///   2. Longest PrefixNoRegex (^~) — if found, skip regex
///   3. Regex/RegexInsensitive in order of appearance
///   4. Longest Prefix match
///   5. Named locations are never matched here
pub fn select_location<'a>(server: &'a ServerBlock, path: &str) -> Option<&'a LocationBlock> {
    let mut exact: Option<&LocationBlock> = None;
    let mut best_prefix_no_regex: Option<(&LocationBlock, usize)> = None; // (block, match_len)
    let mut first_regex: Option<&LocationBlock> = None;
    let mut best_prefix: Option<(&LocationBlock, usize)> = None;

    for loc in &server.locations {
        match &loc.pattern {
            LocationPattern::Exact(p) => {
                if p == path {
                    exact = Some(loc);
                    break; // Exact match wins immediately
                }
            }
            LocationPattern::PrefixNoRegex(p) => {
                if path.starts_with(p.as_str()) {
                    let len = p.len();
                    if best_prefix_no_regex.map_or(true, |(_, l)| len > l) {
                        best_prefix_no_regex = Some((loc, len));
                    }
                }
            }
            LocationPattern::Regex(_, re) => {
                if first_regex.is_none() && re.is_match(path) {
                    first_regex = Some(loc);
                }
            }
            LocationPattern::RegexInsensitive(_, re) => {
                if first_regex.is_none() && re.is_match(path) {
                    first_regex = Some(loc);
                }
            }
            LocationPattern::Prefix(p) => {
                if path.starts_with(p.as_str()) {
                    let len = p.len();
                    if best_prefix.map_or(true, |(_, l)| len > l) {
                        best_prefix = Some((loc, len));
                    }
                }
            }
            LocationPattern::Named(_) => {} // never matched by URI
        }
    }

    if exact.is_some() { return exact; }
    if best_prefix_no_regex.is_some() { return best_prefix_no_regex.map(|(b, _)| b); }
    if first_regex.is_some() { return first_regex; }
    if best_prefix.is_some() { return best_prefix.map(|(b, _)| b); }
    None
}

// ── Named location lookup ─────────────────────────────────────────────────────

pub fn find_named_location<'a>(server: &'a ServerBlock, name: &str) -> Option<&'a LocationBlock> {
    server.locations.iter().find(|loc| {
        matches!(&loc.pattern, LocationPattern::Named(n) if n == name)
    })
}
