// ACME v2 client (RFC 8555) — Let's Encrypt integration.
// No external programs required — pure in-process Rust.

#[cfg(feature = "acme")]
mod inner {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier,
        LetsEncrypt, NewAccount, NewOrder, OrderStatus,
    };
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};
    use tokio::sync::watch;
    use tracing::info;

    const RENEW_AFTER_DAYS: u64 = 60;  // LE certs are 90 days — renew at 60
    const POLL_INTERVAL_SECS: u64 = 3;
    const MAX_POLL_ATTEMPTS: u32 = 30;

    pub struct AcmeConfig {
        pub domains:      Vec<String>,
        pub email:        String,
        pub cert_path:    PathBuf,
        pub key_path:     PathBuf,
        pub account_path: PathBuf,
        pub staging:      bool,
    }

    // ── HTTP-01 challenge token store ─────────────────────────────────────────

    pub struct ChallengeStore {
        tokens: dashmap::DashMap<String, String>,
    }

    impl ChallengeStore {
        pub fn new() -> Arc<Self> {
            Arc::new(Self { tokens: dashmap::DashMap::new() })
        }

        pub fn set(&self, token: &str, key_auth: &str) {
            self.tokens.insert(token.to_owned(), key_auth.to_owned());
        }

        pub fn remove(&self, token: &str) {
            self.tokens.remove(token);
        }

        pub fn get_key_auth(&self, token: &str) -> Option<String> {
            self.tokens.get(token).map(|v| v.clone())
        }
    }

    // ── Main ACME flow ────────────────────────────────────────────────────────

    pub async fn run(
        cfg:       AcmeConfig,
        store:     Arc<ChallengeStore>,
        reload_tx: watch::Sender<()>,
    ) -> Result<()> {
        if !needs_renewal(&cfg.cert_path) {
            info!("ACME: certificate valid, skipping renewal");
            return Ok(());
        }

        info!("ACME: starting certificate issuance for {:?}", cfg.domains);

        let server_url = if cfg.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        let account = load_or_create_account(&cfg.account_path, &cfg.email, server_url).await?;

        let identifiers: Vec<Identifier> = cfg.domains.iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let mut order = account.new_order(&NewOrder {
            identifiers: &identifiers,
        }).await.context("creating ACME order")?;

        // Authorize each domain via HTTP-01.
        let authorizations = order.authorizations().await.context("fetching authorizations")?;

        for auth in &authorizations {
            if auth.status == AuthorizationStatus::Valid {
                continue;
            }
            let challenge = auth.challenges.iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .context("no HTTP-01 challenge offered")?;

            let key_auth = order.key_authorization(challenge);
            store.set(&challenge.token, key_auth.as_str());

            order.set_challenge_ready(&challenge.url).await
                .context("setting challenge ready")?;

            // Poll for validation.
            'poll: for attempt in 0..MAX_POLL_ATTEMPTS {
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                let updated_auths = order.authorizations().await?;
                let updated = updated_auths.iter()
                    .find(|a| a.identifier == auth.identifier)
                    .context("authorization not found in refresh")?;
                match updated.status {
                    AuthorizationStatus::Valid   => break 'poll,
                    AuthorizationStatus::Invalid => {
                        store.remove(&challenge.token);
                        bail!("ACME: validation failed for {:?}", auth.identifier);
                    }
                    _ => {
                        if attempt + 1 >= MAX_POLL_ATTEMPTS {
                            store.remove(&challenge.token);
                            bail!("ACME: validation timed out for {:?}", auth.identifier);
                        }
                        info!("ACME: waiting for validation ({}/{})", attempt+1, MAX_POLL_ATTEMPTS);
                    }
                }
            }
            store.remove(&challenge.token);
        }

        // Wait for order to be ready.
        for attempt in 0..MAX_POLL_ATTEMPTS {
            match order.state().status {
                OrderStatus::Ready | OrderStatus::Valid => break,
                OrderStatus::Invalid => bail!("ACME order invalid"),
                _ => {
                    if attempt + 1 >= MAX_POLL_ATTEMPTS {
                        bail!("ACME order timed out");
                    }
                    tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
                    order.refresh().await.context("refreshing order")?;
                }
            }
        }

        // Generate key pair + CSR with rcgen.
        let key_pair = KeyPair::generate().context("generating key pair")?;
        let mut params = CertificateParams::new(cfg.domains.clone())
            .context("building cert params")?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params.serialize_request(&key_pair).context("serializing CSR")?;

        order.finalize(csr.der()).await.context("finalizing order")?;

        // Download certificate.
        let cert_pem = loop {
            match order.certificate().await.context("downloading certificate")? {
                Some(pem) => break pem,
                None => tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await,
            }
        };

        // Persist.
        if let Some(p) = cfg.cert_path.parent() { std::fs::create_dir_all(p)?; }
        if let Some(p) = cfg.key_path.parent()  { std::fs::create_dir_all(p)?; }
        std::fs::write(&cfg.cert_path, cert_pem.as_bytes()).context("writing cert")?;
        std::fs::write(&cfg.key_path,  key_pair.serialize_pem().as_bytes()).context("writing key")?;

        info!("ACME: certificate written to {}", cfg.cert_path.display());
        let _ = reload_tx.send(());
        Ok(())
    }

    // ── Account helpers ───────────────────────────────────────────────────────

    async fn load_or_create_account(path: &Path, email: &str, server: &str) -> Result<Account> {
        if path.exists() {
            let data = std::fs::read_to_string(path).context("reading account file")?;
            let creds = serde_json::from_str(&data)?;
            let account = Account::from_credentials(creds).await.context("restoring account")?;
            info!("ACME: loaded account from {}", path.display());
            return Ok(account);
        }

        info!("ACME: creating new account ({})", email);
        let (account, creds) = Account::create(
            &NewAccount {
                contact:                 &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing:    false,
            },
            server,
            None,
        ).await.context("creating account")?;

        if let Some(p) = path.parent() { std::fs::create_dir_all(p)?; }
        std::fs::write(path, serde_json::to_string_pretty(&creds)?).context("saving account")?;
        Ok(account)
    }

    fn needs_renewal(cert_path: &Path) -> bool {
        if !cert_path.exists() { return true; }
        let meta = match std::fs::metadata(cert_path) {
            Ok(m) => m,
            Err(_) => return true,
        };
        let age_days = meta.modified().ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs() / 86400)
            .unwrap_or(u64::MAX);
        age_days >= RENEW_AFTER_DAYS
    }
}

#[cfg(feature = "acme")]
pub use inner::*;

#[cfg(not(feature = "acme"))]
pub struct ChallengeStore;
#[cfg(not(feature = "acme"))]
impl ChallengeStore {
    pub fn new() -> std::sync::Arc<Self> { std::sync::Arc::new(ChallengeStore) }
    pub fn get_key_auth(&self, _token: &str) -> Option<String> { None }
}
