use std::path::{Path, PathBuf};

use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream},
    net::TcpListener,
};

use crate::{config::Config, fatal};
const REQUEST_START: &[u8] = b"\r\nFSYNC\r\n";
const REQUEST_END: &[u8] = b"\r\nDONE\r\n";
/// Starts the server
pub async fn serve(config: Config) {
    let listener = fatal!(TcpListener::bind((config.addr.as_str(), config.port)).await);
    log::info!("Listening on {}:{}", config.addr, config.port);
}
/// Listens for incoming connections in an insecure manner
async fn listen_unsecure(listener: TcpListener) {
    log::warn!("Listening in insecure mode is not recommended!");
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                log::info!("Accepted connection from {}", addr);
            }
            Err(err) => {
                log::error!("Failed to accept connection: {err}");
            }
        }
    }
}
fn simplify_path(path: &Path) -> PathBuf {
    todo!()
}
async fn get_handler<S>(
    stream: &mut BufStream<S>,
    addr: std::net::SocketAddr,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    stream.write(REQUEST_START).await?;
    stream.write(b"OUT\r\n").await?;
    let mut data = [0u8; 1024]; // read a kilobyte at a time to put in the output buffer
    let mut file = File::open(path).await?;
    loop {
        let n = file.read(&mut data).await?;
        if n == 0 {
            return Ok(());
        }
        if let Some(pos) = data
            .windows(REQUEST_END.len())
            .position(|w| w == REQUEST_END)
        {
            stream.write(&data[..pos]).await?;
            return Ok(());
        } else {
            stream.write(&data).await?;
            data.fill(0);
        }
    }
}
/// Handles a connection to the server
async fn handle_connection<S>(mut socket: S, addr: std::net::SocketAddr)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = BufStream::with_capacity(0x10000, 0x10000, socket);
    loop {
        // Clear the buffer before handling the request to prevent any old data from being left over
        let mut data = Vec::new();
        if let Err(err) = stream.read_until(b'\n', &mut data).await {
            log::error!("Failed to read from socket: {err}");
            break;
        }
        if data != REQUEST_START {
            log::warn!("Invalid request from {}", addr);
            let _ = stream
                .write(
                    format!(
                        "{0}ERROR\r\nInvalid request{1}",
                        std::str::from_utf8(REQUEST_START).unwrap(),
                        std::str::from_utf8(REQUEST_END).unwrap()
                    )
                    .as_bytes(),
                )
                .await;
            continue;
        }
        data.clear();
        if let Err(err) = stream.read_until(b'\n', &mut data).await {
            log::error!("Failed to read from socket: {err}");
            break;
        }
        match data.trim_ascii() {
            b"GET" => {
                // The next bytes should be the path
                data.clear();
                if let Err(err) = stream.read_until(b'\n', &mut data).await {
                    log::error!("Failed to read from socket: {err}");
                    break;
                }
                if let Ok(path) = std::str::from_utf8(&data).map(Path::new) {
                    if !path.starts_with("/") {
                        log::warn!("Invalid path from {addr}");
                    }
                    let simple_path = simplify_path(path);
                    match get_handler(&mut stream, addr, &simple_path).await {
                        Ok(()) => {
                            let _ = stream.write(REQUEST_END).await;
                        }
                        Err(err) => {
                            log::error!("Failed to get file: {err}");
                            let _ = stream
                                .write(
                                    format!(
                                        "{0}ERROR\r\nFailed to get file{1}",
                                        std::str::from_utf8(REQUEST_START).unwrap(),
                                        std::str::from_utf8(REQUEST_END).unwrap()
                                    )
                                    .as_bytes(),
                                )
                                .await;
                        }
                    }
                }
            }
            b"PUT" =>
            _ => {
                log::warn!("Invalid command from {}", addr);
                if let Err(err) = stream.read_until(b'\n', &mut data).await {
                    log::error!("Failed to read from socket: {err}");
                    break;
                }
            }
        }
    }
}
