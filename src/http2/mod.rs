// HTTP/2 server — handles connections negotiated via ALPN "h2".
// Bridges h2 frames to the existing HTTP/1.1 handler by constructing
// synthetic request bytes and parsing the HTTP/1.1 response back to h2 frames.

#[cfg(feature = "tls")]
pub use h2_impl::serve;

#[cfg(feature = "tls")]
mod h2_impl {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use anyhow::Result;
    use bytes::Bytes;
    use tracing::debug;

    use crate::server::handler::HandlerContext;

    pub async fn serve<IO>(
        io: IO,
        peer: SocketAddr,
        ctx: Arc<HandlerContext>,
    ) -> Result<()>
    where
        IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut conn = h2::server::handshake(io).await?;
        while let Some(result) = conn.accept().await {
            let (req, respond) = result?;
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                if let Err(e) = handle_stream(req, respond, peer, ctx).await {
                    debug!("h2 stream error from {}: {}", peer, e);
                }
            });
        }
        Ok(())
    }

    async fn handle_stream(
        req: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        peer: SocketAddr,
        ctx: Arc<HandlerContext>,
    ) -> Result<()> {
        let (parts, mut body_stream) = req.into_parts();

        // Collect body DATA frames.
        let mut body_bytes: Vec<u8> = Vec::new();
        loop {
            match body_stream.data().await {
                None => break,
                Some(Err(e)) => return Err(e.into()),
                Some(Ok(chunk)) => {
                    let _ = body_stream.flow_control().release_capacity(chunk.len());
                    body_bytes.extend_from_slice(&chunk);
                }
            }
        }

        // Build synthetic HTTP/1.1 request.
        let path_query = parts.uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let mut http1 = format!("{} {} HTTP/1.1\r\n", parts.method.as_str(), path_query);

        // :authority pseudo-header becomes Host.
        if let Some(authority) = parts.uri.authority() {
            http1.push_str(&format!("Host: {}\r\n", authority));
        }

        for (name, value) in &parts.headers {
            let n = name.as_str();
            // Skip pseudo-headers and hop-by-hop headers invalid in HTTP/2.
            if n.starts_with(':')
                || n.eq_ignore_ascii_case("connection")
                || n.eq_ignore_ascii_case("transfer-encoding")
                || n.eq_ignore_ascii_case("upgrade")
                || n.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            if let Ok(v) = value.to_str() {
                http1.push_str(&format!("{}: {}\r\n", n, v));
            }
        }

        if !body_bytes.is_empty() {
            http1.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
        }
        http1.push_str("\r\n");

        let mut raw = http1.into_bytes();
        raw.extend_from_slice(&body_bytes);

        // Dispatch through the existing HTTP/1.1 handler.
        let result = crate::server::handler::handle(&raw, peer, ctx, true).await;

        // Parse HTTP/1.1 response bytes → h2 frames.
        let (status, resp_headers, body) = parse_h1_response(&result.bytes);

        let mut builder = http::Response::builder()
            .status(
                http::StatusCode::from_u16(status)
                    .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
            );
        if let Some(hdrs) = builder.headers_mut() {
            for (name, value) in &resp_headers {
                if let (Ok(n), Ok(v)) = (
                    http::header::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(value),
                ) {
                    hdrs.insert(n, v);
                }
            }
        }
        let response = builder.body(()).unwrap_or_else(|_| http::Response::new(()));

        let end_stream = body.is_empty();
        let mut send = respond.send_response(response, end_stream)?;
        if !end_stream {
            send.send_data(Bytes::copy_from_slice(body), true)?;
        }
        Ok(())
    }

    fn parse_h1_response(bytes: &[u8]) -> (u16, Vec<(String, String)>, &[u8]) {
        let mut header_buf = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut header_buf);
        match resp.parse(bytes) {
            Ok(httparse::Status::Complete(header_end)) => {
                let status = resp.code.unwrap_or(200);
                let hdrs: Vec<(String, String)> = resp.headers.iter()
                    .filter(|h| !h.name.is_empty())
                    .filter(|h| {
                        !h.name.eq_ignore_ascii_case("connection")
                            && !h.name.eq_ignore_ascii_case("transfer-encoding")
                            && !h.name.eq_ignore_ascii_case("keep-alive")
                    })
                    .map(|h| {
                        (h.name.to_owned(), String::from_utf8_lossy(h.value).into_owned())
                    })
                    .collect();
                (status, hdrs, &bytes[header_end..])
            }
            _ => (200, vec![], bytes),
        }
    }
}
