use hyper::header::WWW_AUTHENTICATE;
use hyper::StatusCode;
use reqwest::blocking::Client;
use std::fmt::{Debug, Formatter};
use std::io::{Read, Seek, Write};
use vfs::{FileSystem, SeekAndRead, VfsError, VfsMetadata, VfsResult};

use crate::error::AuthError;
use crate::error::HttpsFSError;
use crate::error::HttpsFSResult;

use crate::protocol::*;

type CredentialProvider = Option<fn(realm: &str) -> (String, String)>;

/// A file system exposed over https
pub struct HttpsFS {
    addr: String,
    client: std::sync::Arc<reqwest::blocking::Client>,
    /// Will be called to get login credentials for the authentication process.
    /// Return value is a tuple: The first part is the user name, the second part the password.
    credentials: CredentialProvider,
}

/// Helper struct for building [HttpsFS] structs
pub struct HttpsFSBuilder {
    port: u16,
    domain: String,
    root_certs: Vec<reqwest::Certificate>,
    credentials: CredentialProvider,
}

struct WritableFile {
    client: std::sync::Arc<reqwest::blocking::Client>,
    addr: String,
    file_name: String,
    position: u64,
}

struct ReadableFile {
    client: std::sync::Arc<reqwest::blocking::Client>,
    addr: String,
    file_name: String,
    position: u64,
}

impl Debug for HttpsFS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("Over Https Exposed File System.")
    }
}

impl HttpsFS {
    /// Returns a builder to create a [HttpsFS]
    pub fn builder(domain: &str) -> HttpsFSBuilder {
        HttpsFSBuilder::new(domain)
    }

    fn load_certificate(filename: &str) -> HttpsFSResult<reqwest::Certificate> {
        let mut buf = Vec::new();
        std::fs::File::open(filename)?.read_to_end(&mut buf)?;
        let cert = reqwest::Certificate::from_pem(&buf)?;
        Ok(cert)
    }

    fn exec_command(&self, cmd: &Command) -> HttpsFSResult<CommandResponse> {
        let req = serde_json::to_string(&cmd)?;
        let mut result = self.client.post(&self.addr).body(req).send()?;
        if result.status() == StatusCode::UNAUTHORIZED {
            let req = serde_json::to_string(&cmd)?;
            result = self
                .authorize(&result, self.client.post(&self.addr).body(req))?
                .send()?;
            if result.status() != StatusCode::OK {
                return Err(HttpsFSError::Auth(AuthError::Failed));
            }
        }
        let result = result.text()?;
        let result: CommandResponse = serde_json::from_str(&result)?;
        Ok(result)
    }

    fn authorize(
        &self,
        prev_response: &reqwest::blocking::Response,
        new_request: reqwest::blocking::RequestBuilder,
    ) -> HttpsFSResult<reqwest::blocking::RequestBuilder> {
        if self.credentials.is_none() {
            return Err(HttpsFSError::Auth(AuthError::NoCredentialSource));
        }
        let prev_headers = prev_response.headers();
        let auth_method = prev_headers
            .get(WWW_AUTHENTICATE)
            .ok_or(HttpsFSError::Auth(AuthError::NoMethodSpecified))?;
        let auth_method = String::from(
            auth_method
                .to_str()
                .map_err(|_| HttpsFSError::InvalidHeader(WWW_AUTHENTICATE.to_string()))?,
        );
        // TODO: this is a fix hack since we currently only support one method. If we start to
        // support more than one authentication method, we have to properly parse this header.
        // Furthermore, currently only the 'PME'-Realm is supported.
        let start_with = "Basic realm=\"PME\"";
        if !auth_method.starts_with(start_with) {
            return Err(HttpsFSError::Auth(AuthError::MethodNotSupported));
        }
        let get_cred = self.credentials.unwrap();
        let (username, password) = get_cred(&"PME");
        let new_request = new_request.basic_auth(username, Some(password));
        Ok(new_request)
    }
}

impl HttpsFSBuilder {
    /// Creates a new builder for a [HttpsFS].
    ///
    /// Takes a domain name to which the HttpsFS will connect.
    pub fn new(domain: &str) -> Self {
        HttpsFSBuilder {
            port: 443,
            domain: String::from(domain),
            root_certs: Vec::new(),
            credentials: None,
        }
    }

    /// Set the port, to which the HttpsFS will connect.
    ///
    /// Default is 443.
    pub fn set_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Overwrites the domain name, which was set while creating the builder.
    pub fn set_domain(mut self, domain: &str) -> Self {
        self.domain = String::from(domain);
        self
    }

    /// Adds an additional root certificate.
    ///
    /// If a self signed certificate is used during, the development,
    /// than the certificate has to be added with this call, otherwise
    /// the [HttpsFS] fails to connect to the [crate::HttpsFSServer].
    pub fn add_root_certificate(mut self, cert: &str) -> Self {
        let cert = HttpsFS::load_certificate(cert).unwrap();
        self.root_certs.push(cert);
        self
    }

    /// If the [crate::HttpsFSServer] request a authentication, than this function will
    /// be called to get the credentials. The first value of the returned tuple
    /// is the user name and the second value is the password.
    pub fn set_credential_provider(
        mut self,
        c_provider: fn(realm: &str) -> (String, String),
    ) -> Self {
        self.credentials = Some(c_provider);
        self
    }

    /// Generates a HttpsFS with the set configuration
    ///
    /// # Error
    ///
    /// Returns an error, if the credential provider was not set.
    pub fn build(self) -> HttpsFSResult<HttpsFS> {
        if self.credentials.is_none() {
            return Err(HttpsFSError::Other {
                message: "HttpsFSBuilder: No credential provider set.".to_string(),
            });
        }
        let mut client = Client::builder().https_only(true).cookie_store(true);
        for cert in self.root_certs {
            client = client.add_root_certificate(cert);
        }

        let client = client.build()?;
        Ok(HttpsFS {
            client: std::sync::Arc::new(client),
            addr: format!("https://{}:{}/", self.domain, self.port),
            credentials: self.credentials,
        })
    }
}

impl Write for WritableFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let req = Command::Write(CommandWrite {
            path: self.file_name.clone(),
            pos: self.position,
            len: buf.len() as u64,
            data: base64::encode(buf),
        });
        let req = serde_json::to_string(&req)?;
        let result = self.client.post(&self.addr).body(req).send();
        if let Err(e) = result {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            ));
        }
        let result = result.unwrap();
        let result = result.text();
        if let Err(e) = result {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            ));
        }
        let result = result.unwrap();
        let result: CommandResponse = serde_json::from_str(&result)?;
        match result {
            CommandResponse::Write(result) => match result {
                Ok(size) => {
                    self.position += size as u64;
                    Ok(size)
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{:?}", e),
                )),
            },
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                String::from("Result doesn't match the request!"),
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        todo!("flush()");
    }
}

impl Read for ReadableFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let req = Command::Read(CommandRead {
            path: self.file_name.clone(),
            pos: self.position,
            len: buf.len() as u64,
        });
        let req = serde_json::to_string(&req)?;
        let result = self.client.post(&self.addr).body(req).send();
        if let Err(e) = result {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            ));
        }
        let result = result.unwrap();
        let result = result.text();
        if let Err(e) = result {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{:?}", e),
            ));
        }
        let result = result.unwrap();
        let result: CommandResponse = serde_json::from_str(&result)?;
        match result {
            CommandResponse::Read(result) => match result {
                Ok((size, data)) => {
                    self.position += size as u64;
                    let decoded_data = base64::decode(data);
                    let mut result = Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        String::from("Faild to decode data"),
                    ));
                    if let Ok(data) = decoded_data {
                        buf[..size].copy_from_slice(&data.as_slice()[..size]);
                        result = Ok(size);
                    }
                    result
                }
                Err(e) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{:?}", e),
                )),
            },
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                String::from("Result doesn't match the request!"),
            )),
        }
    }
}

impl Seek for ReadableFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(offset) => self.position = offset,
            std::io::SeekFrom::Current(offset) => {
                self.position = (self.position as i64 + offset) as u64
            }
            std::io::SeekFrom::End(offset) => {
                let fs = HttpsFS {
                    addr: self.addr.clone(),
                    client: self.client.clone(),
                    credentials: None,
                };
                let meta = fs.metadata(&self.file_name);
                if let Err(e) = meta {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("{:?}", e),
                    ));
                }
                let meta = meta.unwrap();
                self.position = (meta.len as i64 + offset) as u64
            }
        }
        Ok(self.position)
    }
}

impl FileSystem for HttpsFS {
    fn read_dir(&self, path: &str) -> VfsResult<Box<dyn Iterator<Item = String>>> {
        let req = Command::ReadDir(CommandReadDir {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        let result = match result {
            CommandResponse::ReadDir(value) => value,
            _ => {
                return Err(VfsError::Other {
                    message: String::from("Result doesn't match the request!"),
                });
            }
        };
        match result.result {
            Err(e) => Err(VfsError::Other { message: e }),
            Ok(value) => Ok(Box::new(value.into_iter())),
        }
    }

    fn create_dir(&self, path: &str) -> VfsResult<()> {
        let req = Command::CreateDir(CommandCreateDir {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        let result = match result {
            CommandResponse::CreateDir(value) => value,
            _ => {
                return Err(VfsError::Other {
                    message: String::from("Result doesn't match the request!"),
                });
            }
        };

        match result {
            CommandResponseCreateDir::Failed => Err(VfsError::Other {
                message: String::from("Result doesn't match the request!"),
            }),
            CommandResponseCreateDir::Success => Ok(()),
        }
    }

    fn open_file(&self, path: &str) -> VfsResult<Box<dyn SeekAndRead>> {
        if !self.exists(path)? {
            return Err(VfsError::FileNotFound {
                path: path.to_string(),
            });
        }

        Ok(Box::new(ReadableFile {
            client: self.client.clone(),
            addr: self.addr.clone(),
            file_name: String::from(path),
            position: 0,
        }))
    }

    fn create_file(&self, path: &str) -> VfsResult<Box<dyn Write>> {
        let req = Command::CreateFile(CommandCreateFile {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        let result = match result {
            CommandResponse::CreateFile(value) => value,
            _ => {
                return Err(VfsError::Other {
                    message: String::from("Result doesn't match the request!"),
                });
            }
        };

        match result {
            CommandResponseCreateFile::Failed => Err(VfsError::Other {
                message: String::from("Faild to create file!"),
            }),
            CommandResponseCreateFile::Success => Ok(Box::new(WritableFile {
                client: self.client.clone(),
                addr: self.addr.clone(),
                file_name: String::from(path),
                position: 0,
            })),
        }
    }

    fn append_file(&self, path: &str) -> VfsResult<Box<dyn Write>> {
        let meta = self.metadata(path)?;
        Ok(Box::new(WritableFile {
            client: self.client.clone(),
            addr: self.addr.clone(),
            file_name: String::from(path),
            position: meta.len,
        }))
    }

    fn metadata(&self, path: &str) -> VfsResult<VfsMetadata> {
        let req = Command::Metadata(CommandMetadata {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        match result {
            CommandResponse::Metadata(value) => meta_res_convert_cmd_vfs(value),
            _ => Err(VfsError::Other {
                message: String::from("Result doesn't match the request!"),
            }),
        }
    }

    fn exists(&self, path: &str) -> VfsResult<bool> {
        // TODO: Add more logging
        // TODO: try to change return type to VfsResult<bool>
        //       At the moment 'false' does not mean, that the file either does not exist
        //       or that an error has occurred. An developer does not expect this.
        let req = Command::Exists(CommandExists {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        let result = match result {
            CommandResponse::Exists(value) => value,
            _ => {
                return Err(VfsError::Other {
                    message: String::from("Result doesn't match the request!"),
                });
            }
        };
        match result {
            Err(e) => Err(VfsError::Other {
                message: format!("{:?}", e),
            }),
            Ok(val) => Ok(val),
        }
    }

    fn remove_file(&self, path: &str) -> VfsResult<()> {
        let req = Command::RemoveFile(CommandRemoveFile {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        let result = match result {
            CommandResponse::RemoveFile(value) => value,
            _ => {
                return Err(VfsError::Other {
                    message: String::from("Result doesn't match the request!"),
                });
            }
        };

        match result {
            Err(e) => Err(VfsError::Other {
                message: format!("{:?}", e),
            }),
            Ok(_) => Ok(()),
        }
    }

    fn remove_dir(&self, path: &str) -> VfsResult<()> {
        let req = Command::RemoveDir(CommandRemoveDir {
            path: String::from(path),
        });
        let result = self.exec_command(&req)?;
        let result = match result {
            CommandResponse::RemoveDir(value) => value,
            _ => {
                return Err(VfsError::Other {
                    message: String::from("Result doesn't match the request!"),
                });
            }
        };

        match result {
            Err(e) => Err(VfsError::Other {
                message: format!("{:?}", e),
            }),
            Ok(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{HttpsFS, HttpsFSServer};
    use lazy_static::lazy_static;
    use std::sync::{Arc, Mutex};
    use vfs::{test_vfs, MemoryFS};

    // Since we create a HttpsFSServer for each unit test, which are all executed
    // in parallel we have to ensure, that each server is listening on a different
    // port. This is done with this shared variable.
    // WARNING: It will not be tested, whether a port is already used by another
    //          program. In such a case, the corresponding unit test most likely
    //          fails.
    lazy_static! {
        static ref PORT: Arc<Mutex<u16>> = Arc::new(Mutex::new(8344));
    }

    test_vfs!({
        let server_port;
        match PORT.lock() {
            Ok(mut x) => {
                println!("Number: {}", *x);
                server_port = *x;
                *x += 1;
            }
            Err(e) => panic!("Error: {:?}", e),
        }
        std::thread::spawn(move || {
            let fs = MemoryFS::new();
            let server = HttpsFSServer::builder(fs)
                .set_port(server_port)
                .load_certificates("examples/cert/cert.crt")
                .load_private_key("examples/cert/private-key.key")
                .set_credential_validator(|username: &str, password: &str| {
                    username == "user" && password == "pass"
                });
            let result = server.run();
            if let Err(e) = result {
                println!("WARNING: {:?}", e);
            }
        });

        // make sure, that the server is ready for the unit tests
        let duration = std::time::Duration::from_millis(10);
        std::thread::sleep(duration);

        HttpsFS::builder("localhost")
            .set_port(server_port)
            // load self signed certificate
            // WARNING: When the certificate expire, than the unit tests will frail.
            //          In this case, a new certificate hast to be generated.
            .add_root_certificate("examples/cert/cert.crt")
            .set_credential_provider(|_| (String::from("user"), String::from("pass")))
            .build()
            .unwrap()
    });
}
