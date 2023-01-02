#![allow(incomplete_features)]
#![feature(async_fn_in_trait)]

use std::{
    net::ToSocketAddrs,
    os::unix::prelude::{AsRawFd, FromRawFd},
    rc::Rc,
    sync::Arc,
};

use color_eyre::eyre;
use hring::{
    h1, tokio_uring::net::TcpStream, Body, Encoder, ExpectResponseHeaders, Responder, ResponseDone,
    RollMut, ServerDriver,
};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tracing::{debug, info};
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

    let ln = TcpListener::bind("[::]:7007").await?;
    info!("Listening on {}", ln.local_addr()?);

    let conf = Rc::new(h1::ServerConf::default());

    while let Ok((stream, remote_addr)) = ln.accept().await {
        hring::tokio_uring::spawn({
            let acceptor = acceptor.clone();
            let conf = conf.clone();
            async move {
                if let Err(e) = handle_conn(acceptor, stream, remote_addr, conf).await {
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
    conf: Rc<h1::ServerConf>,
) -> Result<(), color_eyre::Report> {
    info!("Accepted connection from {remote_addr}");
    let stream = acceptor.accept(stream).await?;

    debug!("Performed TLS handshake");
    let stream = ktls::config_ktls_server(stream)?;

    debug!("Set up kTLS");
    let (drained, stream) = stream.into_raw();
    let drained = drained.unwrap_or_default();
    debug!("{} bytes already decoded by rustls", drained.len());

    let fd = stream.as_raw_fd();
    std::mem::forget(stream);
    let stream = unsafe { TcpStream::from_raw_fd(fd) };

    let mut buf = RollMut::alloc()?;
    buf.put(&drained[..])?;

    hring::h1::serve(stream, conf, buf, SDriver {}).await?;

    Ok(())
}

struct SDriver {}

impl ServerDriver for SDriver {
    async fn handle<E: Encoder>(
        &self,
        req: hring::Request,
        req_body: &mut impl Body,
        respond: Responder<E, ExpectResponseHeaders>,
    ) -> eyre::Result<Responder<E, ResponseDone>> {
        info!("Handling {:?} {}", req.method, req.path);

        let addr = "httpbingo.org:80"
            .to_socket_addrs()?
            .next()
            .expect("http bingo should be up");
        let transport = Rc::new(TcpStream::connect(addr).await?);
        debug!("Connected to httpbingo");

        let driver = CDriver { respond };

        let (transport, respond) = h1::request(transport, req, req_body, driver).await?;
        // don't re-use transport for now
        drop(transport);

        Ok(respond)
    }
}

struct CDriver<E>
where
    E: Encoder,
{
    respond: Responder<E, ExpectResponseHeaders>,
}

impl<E> h1::ClientDriver for CDriver<E>
where
    E: Encoder,
{
    type Return = Responder<E, ResponseDone>;

    async fn on_informational_response(&mut self, _res: hring::Response) -> eyre::Result<()> {
        // ignore informational responses

        Ok(())
    }

    async fn on_final_response(
        self,
        res: hring::Response,
        body: &mut impl Body,
    ) -> eyre::Result<Self::Return> {
        info!("Client got final response: {}", res.status);
        let respond = self.respond;

        let mut respond = respond.write_final_response(res).await?;

        let trailers = loop {
            debug!("Reading from body {body:?}");
            match body.next_chunk().await? {
                hring::BodyChunk::Chunk(chunk) => {
                    debug!("Client got chunk of len {}", chunk.len());
                    respond.write_chunk(chunk).await?;
                }
                hring::BodyChunk::Done { trailers } => {
                    break trailers;
                }
            }
        };

        respond.finish_body(trailers).await
    }
}
