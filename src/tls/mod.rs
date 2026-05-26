// TLS support via rustls.
// Cert generation: rcgen creates a self-signed certificate if no cert is found.
// No external programs required — everything runs in-process.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

#[cfg(feature = "tls")]
pub use impl_tls::*;

#[cfg(feature = "tls")]
mod impl_tls {
    use super::*;
    use rustls::ServerConfig;
    use rustls_pemfile::{certs, pkcs8_private_keys};

    /// Load a TLS ServerConfig from cert and key files.
    /// If either file is missing, generate a self-signed certificate first.
    pub fn load_server_config(
        cert_path: &Path,
        key_path:  &Path,
        domains:   &[String],
    ) -> Result<Arc<ServerConfig>> {
        // Auto-generate self-signed if files don't exist.
        if !cert_path.exists() || !key_path.exists() {
            generate_self_signed(cert_path, key_path, domains)
                .context("failed to generate self-signed certificate")?;
            info!("generated self-signed cert at {}", cert_path.display());
        }

        load_from_files(cert_path, key_path)
    }

    fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
        let cert_pem = std::fs::read(cert_path)
            .with_context(|| format!("reading cert {}", cert_path.display()))?;
        let key_pem = std::fs::read(key_path)
            .with_context(|| format!("reading key {}", key_path.display()))?;

        let certs = certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parsing certificate chain")?;

        let mut keys = pkcs8_private_keys(&mut key_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("parsing private key")?;

        if keys.is_empty() {
            anyhow::bail!("no PKCS8 private keys found in {}", key_path.display());
        }

        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0));
        let certs = certs.into_iter().map(rustls::pki_types::CertificateDer::from).collect::<Vec<_>>();

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building TLS config")?;

        Ok(Arc::new(config))
    }

    /// Generate a self-signed certificate using rcgen.
    fn generate_self_signed(cert_path: &Path, key_path: &Path, domains: &[String]) -> Result<()> {
        let mut params = rcgen::CertificateParams::new(domains.to_vec()
        ).context("building cert params")?;

        params.not_after  = rcgen::date_time_ymd(2030, 1, 1);
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);

        let key_pair = rcgen::KeyPair::generate().context("generating key pair")?;
        let cert = params.self_signed(&key_pair).context("signing certificate")?;

        // Ensure parent directories exist.
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating cert dir {}", parent.display()))?;
        }
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating key dir {}", parent.display()))?;
        }

        std::fs::write(cert_path, cert.pem()).context("writing cert PEM")?;
        std::fs::write(key_path, key_pair.serialize_pem()).context("writing key PEM")?;

        Ok(())
    }

    /// Perform TLS handshake on an accepted TCP stream.
    pub async fn accept_tls(
        stream:    tokio::net::TcpStream,
        tls_cfg:   Arc<ServerConfig>,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
        acceptor.accept(stream).await.context("TLS handshake failed")
    }
}
