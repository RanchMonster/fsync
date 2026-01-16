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
#[inline(always)]
fn simplify_path(path: &Path) -> Result<PathBuf, String> {
    todo!()
}
#[inline(always)]
fn stream_end(data: &[u8]) -> Option<usize> {
    data.windows(REQUEST_END.len())
        .position(|w| w == REQUEST_END)
}
#[inline(always)]
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
    let mut data = Vec::new();
    let mut file = File::open(path).await?;
    loop {
        let n = file.read(&mut data).await?;
        if n == 0 {
            return Err("Stream ended before the end of the file".into());
        }
        if let Some(pos) = stream_end(&data) {
            stream.write(&data[..pos]).await?;
            return Ok(());
        } else {
            stream.write(&data).await?;
            data.clear();
        }
    }
}

#[inline(always)]
async fn put_handler<S>(
    stream: &mut BufStream<S>,
    addr: std::net::SocketAddr,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    stream.write(REQUEST_START).await?;
    stream.write(b"ACK\r\n").await?;
    let mut data = Vec::new();
    let mut file = File::create(path).await?;
    loop {
        stream.read(&mut data).await?;
        if let Some(pos) = stream_end(&data) {
            file.write_all(&data[..pos]).await?;
            return Ok(());
        } else {
            file.write_all(&data).await?;
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
                    let simple_path = simplify_path(path).expect("todo handle error");
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
            b"PUT" => {
                data.clear();
                if let Err(err) = stream.read_until(b'\n', &mut data).await {
                    log::error!("Failed to read from socket: {err}");
                    break;
                }
                if let Ok(path) = std::str::from_utf8(&data).map(Path::new) {
                    if !path.starts_with("/") {
                        log::warn!("Invalid path from {addr}");
                    }
                    let simple_path = simplify_path(path).expect("todo handle error");
                    match put_handler(&mut stream, addr, &simple_path).await {
                        Ok(()) => {
                            let _ = stream.write(REQUEST_END).await;
                        }
                        Err(err) => {
                            log::error!("Failed to put file: {err}");
                            let _ = stream
                                .write(
                                    format!(
                                        "{0}ERROR\r\nFailed to put file{1}",
                                        std::str::from_utf8(REQUEST_START).unwrap(),
                                        std::str::from_utf8(REQUEST_END).unwrap()
                                    )
                                    .as_bytes(),
                                )
                                .await;
                        }
                    }
                } else {
                    log::warn!("Invalid Path from stream: {addr}");
                    todo!("Handle Invalid stream");
                }
            }
            b"DEL" => {
                // next data in the stream should be the path
                if let Err(err) = stream.read_until(b'\n', &mut data).await {
                    log::error!("Failed to read from socket: {err}");
                    break;
                }
                if let Ok(path) = std::str::from_utf8(&data).map(Path::new) {
                    let simple_path = simplify_path(path).expect("todo handle error");
                }
            }
            b"MKDIR" => {
                todo!("MKDIR")
            }
            b"RMDIR" => {
                todo!("RMDIR")
            }
            b"STAT" => {
                todo!("STAT")
            }
            b"LIST" => {
                todo!("LIST")
            }
            b"CD" => {
                todo!("CD")
            }
            b"PWD" => {
                todo!("PWD")
            }
            b"SLEEP" => {
                todo!("Sleep awaiting for updates form other clients")
            }
            b"QUIT" => {
                break;
            }
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
