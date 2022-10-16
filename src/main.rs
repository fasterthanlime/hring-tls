use std::{
    os::unix::prelude::{AsRawFd, FromRawFd},
    rc::Rc,
    sync::Arc,
};

use color_eyre::eyre;
use hring::tokio_uring::net::TcpStream;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> eyre::Result<()> {
    hring::tokio_uring::start(async_main())
}

async fn async_main() -> eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let pair = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let crt = pair.serialize_der()?;
    let key = pair.serialize_private_key_der();

    let mut server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![rustls::Certificate(crt)], rustls::PrivateKey(key))
        .unwrap();

    server_config.enable_secret_extraction = true;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let acceptor = Rc::new(acceptor);

    let ln = TcpListener::bind("[::]:7000").await?;
    info!("Listening on {}", ln.local_addr()?);

    while let Ok((stream, remote_addr)) = ln.accept().await {
        hring::tokio_uring::spawn({
            let acceptor = acceptor.clone();
            async move {
                if let Err(e) = handle_conn(acceptor, stream, remote_addr).await {
                    tracing::error!(%e, "Error handling connection");
                }
            }
        });
    }

    Ok(())
}

async fn handle_conn(
    acceptor: Rc<tokio_rustls::TlsAcceptor>,
    stream: tokio::net::TcpStream,
    remote_addr: std::net::SocketAddr,
) -> Result<(), color_eyre::Report> {
    info!("Accepted connection from {remote_addr}");
    let stream = acceptor.accept(stream).await?;
    info!("Performed TLS handshake");
    let stream = ktls::config_ktls_server(stream)?;
    info!("Set up kTLS");
    let (drained, stream) = stream.into_raw();
    let drained = drained.unwrap_or_default();
    info!("Drained {} bytes", drained.len());
    assert_eq!(drained.len(), 0);

    let fd = stream.as_raw_fd();
    std::mem::forget(stream);
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    let body = "Hello from hring-tls\n";
    let content_length = body.len();
    let (res, _) = stream
        .write_all(
            format!("HTTP/1.1 200 OK\r\ncontent-length: {content_length}\r\n\r\n{body}")
                .into_bytes(),
        )
        .await;
    res?;

    Ok(())
}
