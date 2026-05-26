// URL rewrite engine — applies rewrite rules with capture group substitution.

use regex::Regex;

use crate::config::types::{RewriteFlag, RewriteRule};

pub enum RewriteOutcome {
    /// Rewrite applied, new URI; re-route (last) or use as-is (break).
    Rewritten { uri: String, stop: bool },
    /// Redirect to new URI.
    Redirect { uri: String, status: u16 },
    /// No rule matched.
    NoMatch,
}

/// Apply rules in order. Returns on first match.
pub fn apply_rewrites(rules: &[RewriteRule], uri: &str) -> RewriteOutcome {
    for rule in rules {
        let Ok(re) = Regex::new(&rule.pattern) else { continue };
        if !re.is_match(uri) { continue; }
        let new_uri = re.replace(uri, rule.replacement.as_str()).into_owned();
        return match rule.flag {
            RewriteFlag::Last      => RewriteOutcome::Rewritten { uri: new_uri, stop: false },
            RewriteFlag::Break     => RewriteOutcome::Rewritten { uri: new_uri, stop: true },
            RewriteFlag::Redirect  => RewriteOutcome::Redirect  { uri: new_uri, status: 302 },
            RewriteFlag::Permanent => RewriteOutcome::Redirect  { uri: new_uri, status: 301 },
        };
    }
    RewriteOutcome::NoMatch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{RewriteRule, RewriteFlag};

    #[test]
    fn redirect_flag() {
        let rules = vec![RewriteRule { pattern: r"^/old/(.*)$".into(), replacement: "/new/$1".into(), flag: RewriteFlag::Redirect }];
        match apply_rewrites(&rules, "/old/page") {
            RewriteOutcome::Redirect { uri, status } => { assert_eq!(uri, "/new/page"); assert_eq!(status, 302); }
            _ => panic!("expected Redirect"),
        }
    }
    #[test]
    fn permanent_flag() {
        let rules = vec![RewriteRule { pattern: r"^/gone$".into(), replacement: "/moved".into(), flag: RewriteFlag::Permanent }];
        match apply_rewrites(&rules, "/gone") {
            RewriteOutcome::Redirect { uri, status } => { assert_eq!(uri, "/moved"); assert_eq!(status, 301); }
            _ => panic!("expected Permanent redirect"),
        }
    }
    #[test]
    fn no_match() {
        let rules = vec![RewriteRule { pattern: r"^/admin/".into(), replacement: "/login".into(), flag: RewriteFlag::Redirect }];
        assert!(matches!(apply_rewrites(&rules, "/public"), RewriteOutcome::NoMatch));
    }
    #[test]
    fn break_flag_stops() {
        let rules = vec![
            RewriteRule { pattern: r"^/a$".into(), replacement: "/b".into(), flag: RewriteFlag::Break },
            RewriteRule { pattern: r"^/b$".into(), replacement: "/c".into(), flag: RewriteFlag::Break },
        ];
        match apply_rewrites(&rules, "/a") {
            RewriteOutcome::Rewritten { uri, stop } => { assert_eq!(uri, "/b"); assert!(stop); }
            _ => panic!("expected Rewritten"),
        }
    }
    #[test]
    fn capture_groups() {
        let rules = vec![RewriteRule { pattern: r"^/user/(\w+)/post/(\d+)$".into(), replacement: "/u/$1/p/$2".into(), flag: RewriteFlag::Last }];
        match apply_rewrites(&rules, "/user/alice/post/42") {
            RewriteOutcome::Rewritten { uri, .. } => assert_eq!(uri, "/u/alice/p/42"),
            _ => panic!("expected Rewritten"),
        }
    }
}

