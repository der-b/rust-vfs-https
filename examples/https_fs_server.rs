use vfs::MemoryFS;
use vfs_https::{HttpsFSResult, HttpsFSServer};

fn main() -> HttpsFSResult<()> {
    // Create a file system, which the server uses to access the files.
    let fs = MemoryFS::new();

    let server = HttpsFSServer::builder(fs)
        // Since this test will not be executed as super user, we are not allowed to listen on
        // a TCP port below 1000, such as the https port 443. Therefore we use a different port.
        .set_port(8443)
        // It is a https server, therefore we need to load a certificate, which the server
        // uses. For the example we use a self signed certificate. If you want to know how to
        // create a self signed certificate, see "/examples/cert/create.sh".
        .load_certificates("examples/cert/cert.crt")
        // We also need to load the private key, which belongs to the certificate.
        .load_private_key("examples/cert/private-key.key")
        // The server needs to authenticate the clients. Therefore we have to provide a method
        // which // validates the user credentials. In this example, only the username 'user'
        // and the password 'pass' is accepted.
        // As authentication process, the 'Basic' method as defined by the
        // [RFC7617](https://tools.ietf.org/html/rfc7617) is used.
        .set_credential_validator(|username: &str, password: &str| {
            username == "user" && password == "pass"
        });

    // Run the server. This call is blocking.
    server.run()
}
