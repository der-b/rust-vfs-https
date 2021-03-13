//!
//! Exposes a [Virtual File Systems (VFS)](https://docs.rs/vfs/) via HTTPS.
//!
//! The [HttpsFSServer] exposes a VFS (implementing [FileSystem](vfs::filesystem::FileSystem)) via HTTPS.
//! [HttpsFS] can be uses to access a [FileSystem](vfs::filesystem::FileSystem) exposed by a [HttpsFSServer].
//!
//! # Example
//!
//! The two examples show the usage of a [HttpsFSServer] and a [HttpsFS]. It is assumed, that the
//! examples are executed in the crate root. Therefore, you can find the referenced files in the
//! crate repository.
//!
//! **Please note**, that it is assumed, that the used certificate is issued for "localhost".
//!
//! You can run the server side examples from the repository root with:
//! ```console
//! cargo run --example https_fs_server
//! ```
//!
//! Start the client side example in another terminal with:
//!
//! ```console
//! cargo run --example https_fs
//! ```
//!
//! ## Server side
//!
//! This example exposes a [memory file system](vfs::MemoryFS) via HTTPS. The content of the file system
//! is lost as soon as the server is terminated.
//!
//! ```no_run
//! # use vfs::MemoryFS;
//! # use vfs_https::{HttpsFSResult, HttpsFSServer};
//! #
//! # fn main() -> HttpsFSResult<()> {
//! // Create a file system, which the server uses to access the files.
//! let fs = MemoryFS::new();
//!
//! let server = HttpsFSServer::builder(fs)
//!     // Since this test will not be executed as super user, we are not allowed to listen on
//!     // a TCP port below 1000, such as the https port 443. Therefore we use a different port.
//!     .set_port(8443)
//!     // It is a https server, therefore we need to load a certificate, which the server
//!     // uses. For the example we use a self signed certificate. If you want to know how to
//!     // create a self signed certificate, see "/examples/cert/create.sh".
//!     .load_certificates("examples/cert/cert.crt")
//!     // We also need to load the private key, which belongs to the certificate.
//!     .load_private_key("examples/cert/private-key.key")
//!     // The server needs to authenticate the clients. Therefore we have to provide a method
//!     // which // validates the user credentials. In this example, only the username 'user'
//!     // and the password 'pass' is accepted.
//!     // As authentication process, the 'Basic' method as defined by the
//!     // [RFC7617](https://tools.ietf.org/html/rfc7617) is used.
//!     .set_credential_validator(|username: &str, password: &str| {
//!         username == "user" && password == "pass"
//!     });
//!
//! // Run the server. This call is blocking.
//! server.run()
//! # }
//! ```
//!
//! ## Client side
//!
//! This example connects to a [HttpsFSServer] and creates a file "example.txt" if it does not exists and appends a
//! new line to it. Afterwards it reads the whole file and prints the content to stdout.
//! As long as the server is not restarted, the output of this program will change with each call.
//!
//! For the usage of [FileSystem](vfs::filesystem::FileSystem) see the crate [vfs].
//! The crate [chrono] is used for the generation of the time stamp.
//!
//! ```no_run
//! # use chrono::prelude::*;
//! # use std::io::Read;
//! # use vfs::VfsPath;
//! # use vfs_https::HttpsFS;
//! #
//! # fn main() -> vfs::VfsResult<()> {
//! // You can not access the server from a different host, since the used certificate is issued
//! // for the localhost and you have to use https://localhost:8443 to access the server. You can
//! // also not use IPs, i.g. https://127.0.0.1:8443, since we didn't issue the certificate
//! // for the IP.
//! let builder = HttpsFS::builder("localhost")
//!     // Set the port used by the server. The default is 443.
//!     .set_port(8443)
//!     // Add the self signed certificate as root certificate. If we don't do this, the client
//!     // refuses to connect to the HttpsFSServer. If the server uses a certificate issued by
//!     // an official certificate authority, than we don't need to add an additional root
//!     // certificate.
//!     .add_root_certificate("examples/cert/cert.crt")
//!     // The client will use the following method to get credentials for the authentication.
//!     .set_credential_provider(|server_msg| {
//!         println!(
//!             "Server request authentification with message \"{}\".",
//!             server_msg
//!         );
//!         (String::from("user"), String::from("pass"))
//!     });
//! let root: VfsPath = builder.build()?.into();
//! let root = root.join("example.txt")?;
//!
//! // make sure that the file exists
//! if !root.exists()? {
//!     root.create_file()?;
//! }
//!
//! // add a new line to the file
//! let mut file = root.append_file()?;
//! let time = Local::now();
//! let line = format!("{}: Hello HttpsFS!\n", time);
//! file.write(line.as_bytes())?;
//!
//! // open file reading
//! let file = root.open_file()?;
//!
//! // One should really use a BufReader, which reads files in chunks of 8kb.
//! // The Read trait, issues a new request to the HttpsFSServer with each call,
//! // even if only on byte is read. The headers of the http-protocol needs
//! // several hundred bytes, which makes small reads inefficient.
//! let mut buffed_file = std::io::BufReader::new(file);
//!
//! // read file content
//! let mut content = String::new();
//! buffed_file.read_to_string(&mut content)?;
//!
//! println!("Content of example.txt: \n{}", content);
//! #
//! # Ok(())
//! # }
//! ```
//!
//!
//! # TODOs
//! - Implement a [CGI](https://en.wikipedia.org/wiki/Common_Gateway_Interface)
//!   version of the HttpsFSServer.
//!     * This would allow a user to use any webserver provided by its
//!       favorite web-hoster as an infrastructure. The advantage is, that the
//!       web-hoster can overtake the certificate management, which is often
//!       perceived as a liability.
//! - Write a HttpsFS version, which can be compiled to WebAssembly
//! - Consider to provide an non-blocking version of HttpsFS
//! - Do version check after connecting to a HttpsFSServer

#![warn(missing_docs)]

mod error;
mod httpsfs;
mod protocol;
mod server;
pub use error::{HttpsFSError, HttpsFSResult};
pub use httpsfs::{HttpsFS, HttpsFSBuilder};
pub use server::{HttpsFSServer, HttpsFSServerBuilder};
