use async_stream::stream;
use chrono::prelude::*;
use core::task::{Context, Poll};
use futures_util::stream::Stream;
use hyper::header::{AUTHORIZATION, COOKIE, SET_COOKIE, WWW_AUTHENTICATE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use rand::prelude::*;
use rustls::internal::pemfile;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read, Seek, Write};
use std::pin::Pin;
use std::sync;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use vfs::FileSystem;

use crate::error::{HttpsFSError, HttpsFSResult};
use crate::protocol::*;

/// A https server providing a interface for HttpsFS
pub struct HttpsFSServer<T: FileSystem> {
    port: u16,
    certs: Vec<rustls::Certificate>,
    private_key: rustls::PrivateKey,
    file_system: std::sync::Arc<std::sync::Mutex<T>>,
    client_data: std::sync::Arc<std::sync::Mutex<HashMap<String, HttpsFSServerClientData>>>,
    credential_validator: fn(user: &str, password: &str) -> bool,
}

/// Helper structure for building HttpsFS structs
pub struct HttpsFSServerBuilder<T: FileSystem> {
    port: u16,
    certs: Option<String>,
    private_key: Option<String>,
    file_system: T,
    credential_validator: Option<fn(user: &str, password: &str) -> bool>,
}

#[derive(Debug)]
struct HttpsFSServerClientData {
    last_use: DateTime<Local>,
    authorized: bool,
}

impl HttpsFSServerClientData {
    fn new() -> Self {
        HttpsFSServerClientData {
            last_use: Local::now(),
            authorized: false,
        }
    }
}

impl<T: FileSystem> HttpsFSServer<T> {
    /// Starts a builder of a [HttpsFSServer] with an object implementing the [FileSystem](vfs::filesystem::FileSystem) trait.
    pub fn builder(fs: T) -> HttpsFSServerBuilder<T> {
        HttpsFSServerBuilder::new(fs)
    }

    fn new(
        port: u16,
        certs: &str,
        private_key: &str,
        file_system: T,
        credential_validator: fn(user: &str, password: &str) -> bool,
    ) -> Self {
        // Initially i tried to store a hyper::server::Server object in HttpsFSServer.
        // I failed, since this type is a very complicated generic and i could
        // not figure out, how to write down the type.
        // The type definition is:
        //
        // impl<I, IO, IE, S, E, B> Server<I, S, E>
        //   where
        //     I: Accept<Conn = IO, Error = IE>,
        //     IE: Into<Box<dyn StdError + Send + Sync>>,
        //     IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        //     S: MakeServiceRef<IO, Body, ResBody = B>,
        //     S::Error: Into<Box<dyn StdError + Send + Sync>>,
        //     B: HttpBody + Send + Sync + 'static,
        //     B::Error: Into<Box<dyn StdError + Send + Sync>>,
        //     E: ConnStreamExec<<S::Service as HttpService<Body>>::Future, B>,
        //     E: NewSvcExec<IO, S::Future, S::Service, E, GracefulWatcher>,
        //
        // This makes this struct almost impossible to use in situation, where one can not
        // rely on rust type inference system. Currently i consider this as bad API design.
        let private_key = load_private_key(private_key).unwrap();
        let certs = load_certs(certs).unwrap();
        HttpsFSServer {
            port,
            certs,
            private_key,
            file_system: std::sync::Arc::new(std::sync::Mutex::new(file_system)),
            client_data: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            credential_validator,
        }
    }

    /// Start the server
    #[tokio::main]
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = format!("127.0.0.1:{}", self.port);
        let fs = self.file_system.clone();
        let cd = self.client_data.clone();
        let cv = self.credential_validator;

        let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        cfg.set_single_cert(self.certs.clone(), self.private_key.clone())
            .map_err(|e| Error::new(ErrorKind::Other, format!("{}", e)))?;
        cfg.set_protocols(&[b"http/2".to_vec(), b"http/1.1".to_vec()]);
        let tls_conf = sync::Arc::new(cfg);

        let tcp = TcpListener::bind(&addr).await?;
        let tls_acceptor = TlsAcceptor::from(tls_conf);

        let incoming_tls_stream = stream! {
            loop {
                let (socket, _) = tcp.accept().await?;
                let stream = tls_acceptor.accept(socket);
                let res = stream.await;
                if let Err(e) = res {
                    println!("TLS Error: {:?}", e);
                    continue;
                }
                yield res;
            }
        };

        // The next let statement is rather complicated:
        // It is a variant of the [Factory method pattern](https://en.wikipedia.org/wiki/Factory_method_pattern)
        // implemented by two closures. In this case, i named the first closure 'factory' and the
        // second closure 'product' (see comments). This is needed, since 'hyper' serves each
        // connection with a different instance of a service. Since we don't know, how many
        // connections have to be served in the future, we give 'hyper' this factory and than it
        // can create services on demand.  But our factory is not producing the service immediately.
        // If we call our factory, it only creates an instruction book and the needed materials, so
        // that we can build the service by ourself later. That means, we get a
        // [future](https://docs.rs/futures/0.3.12/futures/) from our factory, which can be
        // executed later to create our service. Even the service method is a future.
        //
        // The tricky part is, that a closure can be moved out of the current contest.
        // Therefore, we can not borrow any values from the current context, since the values
        // of the current context might have a shorter lifetime than our 'factory'. In this
        // example, since we wait until the server finishes its execution in the same
        // context ("server.await?;"). I'm not sure, whether the lifetime analysis of the rust
        // does not under stand that or whether a 'static lifetime is required by some types
        // provided by hyper.
        // The result of this is, that we cannot have an object which implements FileSystem
        // in the HttpsFSServer and than borrow it the factory and than to the service even
        // if we know, that HttpsFSServer lives as long as the hyper instance.
        //
        // 'hyper' also forces us, to use types, which have implemented the 'Send' trait. Therefor
        // we can not use a single-threaded reference count (std::rc:Rc) but have to use a
        // thread save variant (std::sync::Arc) instead.
        let service_factory = make_service_fn(
            // factory closure
            move |_| {
                let fs = fs.clone();
                let cd = cd.clone();
                async move {
                    // return a future (instruction book to create or)
                    Ok::<_, Error>(service_fn(
                        // product closure
                        move |request| {
                            let fs = fs.clone();
                            let cd = cd.clone();
                            HttpsFSServer::https_fs_service(fs, cd, cv, request)
                        },
                    ))
                }
            },
        );

        let server = Server::builder(HyperAcceptor {
            acceptor: Box::pin(incoming_tls_stream),
        })
        .serve(service_factory);

        println!("Starting to serve on https://{}.", addr);

        server.await?;

        Ok(())
    }

    async fn https_fs_service(
        file_system: std::sync::Arc<std::sync::Mutex<T>>,
        client_data: std::sync::Arc<std::sync::Mutex<HashMap<String, HttpsFSServerClientData>>>,
        credential_validator: fn(user: &str, pass: &str) -> bool,
        req: Request<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        // TODO: Separate Session, authorization and content handling in different methods.
        let mut response = Response::new(Body::empty());

        HttpsFSServer::<T>::clean_up_client_data(&client_data);
        let sess_id = HttpsFSServer::<T>::get_session_id(&client_data, &req, &mut response);
        let auth_res =
            HttpsFSServer::<T>::try_auth(&client_data, &sess_id, &credential_validator, &req);
        match auth_res {
            Err(()) => {
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            }
            Ok(value) => {
                if !value {
                    *response.status_mut() = StatusCode::UNAUTHORIZED;
                    response.headers_mut().insert(
                        WWW_AUTHENTICATE,
                        "Basic realm=\"PME\", charset=\"UTF-8\"".parse().unwrap(),
                    );
                    return Ok(response);
                }
            }
        }

        match (req.method(), req.uri().path()) {
            (&Method::POST, "/") => {
                let body = hyper::body::to_bytes(req.into_body()).await?;
                let req: Result<Command, serde_json::Error> = serde_json::from_slice(&body);
                //println!("Server request: {:?}", req);

                match req {
                    // TODO: Add more logging for debug
                    Err(_) => *response.status_mut() = StatusCode::BAD_REQUEST,
                    Ok(value) => {
                        let res;
                        {
                            let file_system = file_system.lock().unwrap();
                            res = HttpsFSServer::<T>::handle_command(&value, &*file_system);
                        }
                        let res = serde_json::to_string(&res);
                        //println!("Server response: {:?}", res);
                        match res {
                            // TODO: Add more logging for debug
                            Err(_) => *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR,
                            Ok(value) => *response.body_mut() = Body::from(value),
                        }
                    }
                }
            }
            _ => {
                *response.status_mut() = StatusCode::NOT_FOUND;
            }
        };
        Ok(response)
    }

    fn handle_command(command: &Command, file_system: &dyn FileSystem) -> CommandResponse {
        match command {
            Command::Exists(param) => CommandResponse::Exists({
                file_system
                    .exists(&param.path)
                    .map_err(CommandResponseError::from)
            }),
            Command::Metadata(param) => CommandResponse::Metadata(meta_res_convert_vfs_cmd(
                file_system.metadata(&param.path),
            )),
            Command::CreateFile(param) => CommandResponse::CreateFile(
                CommandResponseCreateFile::from(file_system.create_file(&param.path)),
            ),
            Command::RemoveFile(param) => CommandResponse::RemoveFile({
                file_system
                    .remove_file(&param.path)
                    .map_err(CommandResponseError::from)
            }),
            Command::Write(param) => {
                CommandResponse::Write(HttpsFSServer::<T>::write(&param, file_system))
            }
            Command::Read(param) => {
                CommandResponse::Read(HttpsFSServer::<T>::read(&param, file_system))
            }
            Command::CreateDir(param) => CommandResponse::CreateDir(
                CommandResponseCreateDir::from(file_system.create_dir(&param.path)),
            ),
            Command::ReadDir(param) => CommandResponse::ReadDir(CommandResponseReadDir::from(
                file_system.read_dir(&param.path),
            )),
            Command::RemoveDir(param) => CommandResponse::RemoveDir(
                file_system
                    .remove_dir(&param.path)
                    .map_err(CommandResponseError::from),
            ),
        }
    }

    fn write(
        cmd: &CommandWrite,
        file_system: &dyn FileSystem,
    ) -> Result<usize, CommandResponseError> {
        let mut file = file_system.append_file(&cmd.path)?;
        let data = base64::decode(&cmd.data);
        if let Err(e) = data {
            return Err(CommandResponseError::Other {
                message: format!("Faild to decode data: {:?}", e),
            });
        }
        let data = data.unwrap();
        Ok(file.write(&data)?)
    }

    fn read(
        cmd: &CommandRead,
        file_system: &dyn FileSystem,
    ) -> Result<(usize, String), CommandResponseError> {
        let mut file = file_system.open_file(&cmd.path)?;

        let mut data: Vec<u8> = vec![0; cmd.len as usize];

        let seek_res = file.seek(std::io::SeekFrom::Start(cmd.pos));
        if let Err(e) = seek_res {
            return Err(CommandResponseError::IoError(format!("{:?}", e)));
        }

        let len = file.read(data.as_mut_slice())?;
        let data = base64::encode(&mut data.as_mut_slice()[..len]);

        Ok((len, data))
    }

    fn clean_up_client_data(
        client_data: &std::sync::Arc<std::sync::Mutex<HashMap<String, HttpsFSServerClientData>>>,
    ) {
        let mut client_data = client_data.lock().unwrap();
        let now = Local::now();
        let dur = chrono::Duration::minutes(15);
        let mut dummy = HashMap::new();

        std::mem::swap(&mut *client_data, &mut dummy);

        dummy = dummy
            .into_iter()
            .filter(|(_, v)| (now - v.last_use) <= dur)
            .collect();

        std::mem::swap(&mut *client_data, &mut dummy);
    }

    fn get_session_id(
        client_data: &std::sync::Arc<std::sync::Mutex<HashMap<String, HttpsFSServerClientData>>>,
        request: &Request<Body>,
        response: &mut Response<Body>,
    ) -> String {
        let mut sess_id = String::new();
        let headers = request.headers();
        if headers.contains_key(COOKIE) {
            // session is already established
            let cookie = headers[COOKIE].as_bytes();
            if cookie.starts_with(b"session=") {
                sess_id = match cookie.get("session=".len()..) {
                    None => String::new(),
                    Some(value) => match std::str::from_utf8(value) {
                        Err(_) => String::new(),
                        Ok(value) => String::from(value),
                    },
                };
                let mut client_data = client_data.lock().unwrap();
                match client_data.get_mut(&sess_id) {
                    // we didn't found the session id in our database,
                    // therefore we delete the id and a new one will be created.
                    None => sess_id = String::new(),
                    Some(value) => value.last_use = Local::now(),
                };
            }
        }

        if sess_id.is_empty() {
            let mut client_data = client_data.lock().unwrap();
            while sess_id.is_empty() || client_data.contains_key(&sess_id) {
                let mut sess_id_raw = [0_u8; 30];
                let mut rng = thread_rng();
                for x in &mut sess_id_raw {
                    *x = rng.gen();
                }
                // to ensure, that session id is printable
                sess_id = base64::encode(sess_id_raw);
            }
            let cookie = format!("session={}", sess_id);
            response
                .headers_mut()
                .insert(SET_COOKIE, cookie.parse().unwrap());
            client_data.insert(sess_id.clone(), HttpsFSServerClientData::new());
        }

        sess_id
    }

    fn try_auth(
        client_data: &std::sync::Arc<std::sync::Mutex<HashMap<String, HttpsFSServerClientData>>>,
        sess_id: &str,
        credential_validator: &fn(user: &str, pass: &str) -> bool,
        request: &Request<Body>,
    ) -> Result<bool, ()> {
        let mut client_data = client_data.lock().unwrap();
        let sess_data = client_data.get_mut(sess_id);
        if sess_data.is_none() {
            return Err(());
        }
        let sess_data = sess_data.unwrap();

        // try to authenticate client
        if !sess_data.authorized {
            let headers = request.headers();
            let auth = headers.get(AUTHORIZATION);
            if auth.is_none() {
                return Ok(false);
            }
            let auth = auth.unwrap().to_str();
            if auth.is_err() {
                return Ok(false);
            }
            let auth = auth.unwrap();
            let starts = "Basic ";
            if !auth.starts_with(starts) {
                return Ok(false);
            }
            let auth = base64::decode(&auth[starts.len()..]);
            if auth.is_err() {
                return Ok(false);
            }
            let auth = auth.unwrap();
            let auth = String::from_utf8(auth);
            if auth.is_err() {
                return Ok(false);
            }
            let auth = auth.unwrap();
            let mut auth_it = auth.split(':');
            let username = auth_it.next();
            if username.is_none() {
                return Ok(false);
            }
            let username = username.unwrap();
            let pass = auth_it.next();
            if pass.is_none() {
                return Ok(false);
            }
            let pass = pass.unwrap();
            if credential_validator(username, pass) {
                sess_data.authorized = true;
            }
        }

        // if not authenticated, than inform client about it.
        if sess_data.authorized {
            return Ok(true);
        }

        Ok(false)
    }
}

impl<T: FileSystem> HttpsFSServerBuilder<T> {
    /// Creates a new builder for a [HttpsFSServer].
    ///
    /// Takes a FileSystem as argument, which will exposed via HTTPS.
    pub fn new(fs: T) -> Self {
        HttpsFSServerBuilder {
            port: 443,
            certs: None,
            private_key: None,
            file_system: fs,
            credential_validator: None,
        }
    }

    /// Sets the port on which the server will listen.
    pub fn set_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }


    /// Loads a private key from file.
    ///
    /// The argument 'private_key' is the path to the file containing the private key.
    pub fn load_private_key(mut self, private_key: &str) -> Self {
        self.private_key = Some(String::from(private_key));
        self
    }

    /// Loads the certificate from a file.
    ///
    /// The argument 'certs' is the path to the file containing a certificate.
    pub fn load_certificates(mut self, certs: &str) -> Self {
        self.certs = Some(String::from(certs));
        self
    }

    /// Sets a function, which serves as a credential validator.
    pub fn set_credential_validator(
        mut self,
        credential_validator: fn(user: &str, password: &str) -> bool,
    ) -> Self {
        self.credential_validator = Some(credential_validator);
        self
    }

    /// Starts listening on the configured port.
    ///
    /// # Panics
    ///
    /// This function panics if one of the following conditions is fulfilled.
    /// - no certificate was set
    /// - no private key was set
    /// - no credential validator was not set
    pub fn run(self) -> HttpsFSResult<()> {
        if self.certs.is_none() {
            panic!("Certificate file was not set. Use set_certificates().");
        }
        if self.private_key.is_none() {
            panic!("Private key file was not set. Use set_private_key().");
        }
        if self.credential_validator.is_none() {
            panic!("Credential validator was not set. Use set_credential_validator().");
        }
        let mut server = HttpsFSServer::new(
            self.port,
            &self.certs.unwrap(),
            &self.private_key.unwrap(),
            self.file_system,
            self.credential_validator.unwrap(),
        );
        let res = server.run();
        match res {
            Err(e) => Err(HttpsFSError::Other {
                message: e.to_string(),
            }),
            Ok(()) => Ok(()),
        }
    }
}

struct HyperAcceptor {
    acceptor: Pin<Box<dyn Stream<Item = Result<TlsStream<TcpStream>, Error>>>>,
}

impl hyper::server::accept::Accept for HyperAcceptor {
    type Conn = TlsStream<TcpStream>;
    type Error = Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        Pin::new(&mut self.acceptor).poll_next(cx)
    }
}

/// Load public certificate from file
fn load_certs(filename: &str) -> std::io::Result<Vec<rustls::Certificate>> {
    // Open certificate file
    let cert_file = std::fs::File::open(filename).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("faild to open {}: {}", filename, e),
        )
    })?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    pemfile::certs(&mut cert_reader)
        .map_err(|_| Error::new(ErrorKind::Other, "faild to load certificate"))
}

/// Load private key from file
fn load_private_key(filename: &str) -> std::io::Result<rustls::PrivateKey> {
    // Open keyfile
    let key_file = std::fs::File::open(filename).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("faild to open {}: {}", filename, e),
        )
    })?;
    let mut key_reader = std::io::BufReader::new(key_file);

    // Load and return a single private key
    let keys = pemfile::pkcs8_private_keys(&mut key_reader)
        .map_err(|_| Error::new(ErrorKind::Other, "failed to load private pkcs8 key"))?;
    if keys.len() == 1 {
        return Ok(keys[0].clone());
    }

    let keys = pemfile::rsa_private_keys(&mut key_reader)
        .map_err(|_| Error::new(ErrorKind::Other, "failed to load private rsa key"))?;
    if keys.len() != 1 {
        println!("len: {}", keys.len());
        return Err(Error::new(
            ErrorKind::Other,
            "expected a single private key",
        ));
    }
    Ok(keys[0].clone())
}
