//! Content-addressed serving for the browser widget bundle.
//!
//! The widget is not one file. `captcha-widget.js` fetches
//! `captcha-worker.js` at runtime, which in turn pulls
//! `vendor/argon2.umd.min.js`, and the stylesheet is a fourth request. Those
//! are four independent browser cache entries that all have to agree with
//! each other *and* with the server's wire format — the worker's
//! `solveArgon2id` has to match `compute_argon2id`, and the widget has to
//! understand whatever `algorithm` the puzzle response names.
//!
//! Served from plain unversioned paths with no `Cache-Control`, browsers
//! apply heuristic freshness, so a visitor could hold a new widget against a
//! stale worker for an unbounded window after any deploy that touched the PoW
//! contract. Switching the default algorithm to Argon2id is exactly that
//! shape of change: a cached SHA-256-only worker cannot solve the puzzle it
//! gets handed, and no server-side rollback reaches it.
//!
//! The fix is the shape Turnstile and hCaptcha use. One *mutable* entry point
//! at a stable URL integrators embed forever (`/v1/widget.js`, short TTL),
//! pointing at an *immutable* directory keyed by a hash of the asset contents
//! (`/assets/<hash>/…`, cached for a year). Any change to any asset changes
//! the hash, so the bundle moves atomically and a half-updated combination is
//! not representable. A build that changes no asset keeps the hash, so
//! redeploys don't needlessly evict warm caches — which a git-SHA stamp would
//! do on every commit, and which `.dockerignore` excluding `/.git` would make
//! awkward to compute in the image anyway.

use std::path::Path;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// Files whose contents determine the bundle hash.
///
/// Every asset the widget pulls at runtime belongs here: if a file can change
/// the client's behaviour but is not hashed, the version stops being a
/// truthful description of the bundle and stale-mixing comes back. The
/// operator-facing pages under `static/` (`admin.html`, `testsite.html`, the
/// info pages) are deliberately absent — nothing loads them as part of a
/// widget, they keep being served from `/static/`, and including them would
/// churn the hash for edits that cannot affect an embed.
const HASHED_ASSETS: [&str; 4] = [
    "captcha-widget.js",
    "captcha-worker.js",
    "captcha-widget.css",
    "vendor/argon2.umd.min.js",
];

/// Token in `captcha-widget.js` that the entry-point route rewrites to the
/// hashed asset directory.
///
/// The same file is also served verbatim from `/static/` (the legacy embed
/// path) and from inside `/assets/<hash>/`, where no substitution happens.
/// The widget therefore treats an unsubstituted placeholder as "resolve my
/// siblings relative to my own URL" — see `resolveAssetBase` in the widget.
/// That keeps one source file correct on all three paths instead of needing a
/// build step to emit variants.
const ASSET_BASE_PLACEHOLDER: &str = "__BOLLWARK_ASSET_BASE__";

/// URL prefix under which the immutable, content-hashed bundle is mounted.
pub const ASSET_MOUNT: &str = "/assets";

/// `Cache-Control` for the mutable entry point.
///
/// Short rather than `no-store`: the entry point is on the critical path of
/// every embed, so it wants to be cacheable, but five minutes bounds how long
/// a bad deploy can keep reaching visitors. This is the only asset URL whose
/// contents ever change, which is what makes the year-long TTL below safe.
const ENTRY_CACHE_CONTROL: &str = "public, max-age=300";

/// `Cache-Control` for everything under `/assets/<hash>/`.
///
/// Safe at a year precisely because the path contains the content hash: a
/// changed file is a different URL, never a stale hit.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// `Cache-Control` for the legacy unversioned `/static/` tree.
///
/// Same bound as the entry point, and for the same reason: nothing under
/// `/static/` is content-addressed, so this is the longest a stale copy can
/// outlive a deploy. Before it existed the answer was "however long the
/// browser's heuristic freshness decides", which is what made a widget/worker
/// version skew unbounded.
pub const LEGACY_CACHE_CONTROL: &str = ENTRY_CACHE_CONTROL;

/// The widget entry point, resolved once at router construction.
pub struct WidgetBundle {
    /// Short content hash over [`HASHED_ASSETS`], used as the immutable path
    /// segment.
    pub version: String,
    /// `captcha-widget.js` with [`ASSET_BASE_PLACEHOLDER`] substituted for
    /// this bundle's asset directory.
    source: String,
}

impl WidgetBundle {
    /// Read and hash the bundle out of `static_dir`.
    ///
    /// Returns `None` if any hashed asset is missing or unreadable, which the
    /// caller treats as "don't mount the versioned routes at all". Degrading
    /// to no entry point is better than serving one that points at an asset
    /// directory we could not verify; the legacy `/static/` paths keep
    /// working either way, so a partial `STATIC_DIR` still yields a
    /// functioning (if unversioned) widget rather than a boot failure.
    pub fn load(static_dir: &str) -> Option<Self> {
        let dir = Path::new(static_dir);
        let mut hasher = Sha256::new();

        for name in HASHED_ASSETS {
            let path = dir.join(name);
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        asset = name,
                        path = %path.display(),
                        error = %e,
                        "widget asset unreadable; serving unversioned /static assets only"
                    );
                    return None;
                }
            };
            // Length-prefix each entry so that two different splits of the
            // same total byte stream can't collide onto one hash.
            hasher.update(name.as_bytes());
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }

        // 8 bytes of SHA-256. This is a cache key, not a security boundary —
        // it only has to make an accidental collision between two builds
        // implausible, and it keeps the URL short enough to read in a log.
        let version = hex::encode(&hasher.finalize()[..8]);

        let raw = std::fs::read_to_string(dir.join("captcha-widget.js")).ok()?;
        let source = raw.replace(ASSET_BASE_PLACEHOLDER, &format!("{ASSET_MOUNT}/{version}"));

        Some(Self { version, source })
    }

    /// Path this bundle's immutable assets are mounted at.
    pub fn mount_path(&self) -> String {
        format!("{ASSET_MOUNT}/{}", self.version)
    }

    /// Serve the entry point.
    pub fn respond(&self) -> Response {
        (
            [
                (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                (header::CACHE_CONTROL, ENTRY_CACHE_CONTROL),
            ],
            self.source.clone(),
        )
            .into_response()
    }
}

/// Fallback when no bundle could be loaded, so the route still answers
/// predictably instead of 404-ing as if the URL were wrong.
pub async fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "widget assets unavailable; check STATIC_DIR",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repo's own `static/` is the bundle every deployment ships, so a
    /// missing or renamed asset should fail here rather than at boot.
    #[test]
    fn loads_the_repo_bundle() {
        let bundle = WidgetBundle::load("static").expect("static/ bundle should load");
        assert_eq!(bundle.version.len(), 16, "8 bytes hex-encoded");
        assert!(bundle.version.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The whole scheme rests on the entry point no longer containing the
    /// placeholder: if substitution silently stopped matching, the widget
    /// would fall back to unversioned `/static` paths and the skew window
    /// would reopen without anything failing loudly.
    #[test]
    fn entry_point_has_the_asset_base_substituted() {
        let bundle = WidgetBundle::load("static").expect("static/ bundle should load");
        assert!(
            !bundle.source.contains(ASSET_BASE_PLACEHOLDER),
            "placeholder must be rewritten in the served entry point"
        );
        assert!(bundle.source.contains(&bundle.mount_path()));
    }

    /// Content-addressing is only useful if it is stable across runs — an
    /// unstable hash would evict every cache on every restart.
    #[test]
    fn version_is_deterministic() {
        let a = WidgetBundle::load("static").expect("bundle");
        let b = WidgetBundle::load("static").expect("bundle");
        assert_eq!(a.version, b.version);
    }

    #[test]
    fn missing_static_dir_yields_no_bundle() {
        assert!(WidgetBundle::load("static/does-not-exist").is_none());
    }
}
