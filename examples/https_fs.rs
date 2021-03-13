use chrono::prelude::*;
use std::io::Read;
use vfs::VfsPath;
use vfs_https::HttpsFS;

// This example creates a file "example.txt" if not exists and appends a new line to it.
// Afterwards it reads the whole file and prints the content to the stdout.
//
// As long as the server is not restarted, the output of this program will
// change with each call. Since the example HttpsFSServer (https_fs_server.rs) is using a MemoryFS,
// the content of the server are lost after a restart.
fn main() -> vfs::VfsResult<()> {
    // You can not access the server from a different host, since the used certificate is issued
    // for the localhost and you have to use https://localhost:8443 to access the server. You can
    // also not use IPs, i.g. https://127.0.0.1:8443, since we didn't issue the certificate
    // for the IP.
    let builder = HttpsFS::builder("localhost")
        // Set the port used by the server. The default is 443.
        .set_port(8443)
        // Add the self signed certificate as root certificate. If we don't do this, the client
        // refuses to connect to the HttpsFSServer. If the server uses a certificate issued by
        // an official certificate authority, than we don't need to add an additional root
        // certificate.
        .add_root_certificate("examples/cert/cert.crt")
        // The client will use the following method to get credentials for the authentication.
        .set_credential_provider(|server_msg| {
            println!(
                "Server request authentification with message \"{}\".",
                server_msg
            );
            (String::from("user"), String::from("pass"))
        });
    let root: VfsPath = builder.build()?.into();
    let root = root.join("example.txt")?;

    // make sure that the file exists
    if !root.exists()? {
        root.create_file()?;
    }

    // add a new line to the file
    let mut file = root.append_file()?;
    let time = Local::now();
    let line = format!("{}: Hello HttpsFS!\n", time);
    file.write(line.as_bytes())?;

    // open file reading
    let file = root.open_file()?;

    // One should really use a BufReader, which reads files in chunks of 8kb.
    // The Read trait, issues a new request to the HttpsFSServer with each call,
    // even if only on byte is read. The headers of the http-protocol needs
    // several hundred bytes, which makes small reads inefficient.
    let mut buffed_file = std::io::BufReader::new(file);

    // read file content
    let mut content = String::new();
    buffed_file.read_to_string(&mut content)?;

    println!("Content of example.txt: \n{}", content);

    Ok(())
}
