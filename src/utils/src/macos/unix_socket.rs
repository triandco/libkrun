//! AF_UNIX paths longer than `sockaddr_un.sun_path`.
//!
//! `SockAddr::unix` and `std::os::unix::net` refuse a path that does not fit
//! `sun_path` (103 bytes on macOS). The macOS kernel takes an address up to
//! `SOCK_MAXADDRLEN` (255 bytes), so a longer path gets an address built by
//! hand. A sandboxed app needs this: its container path alone uses most of the
//! 103 bytes.

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::Path;

/// The longest path that fits `sockaddr_un.sun_path` with its NUL.
const SUN_PATH_MAX: usize = 103;
/// `sun_len` and `sun_family` come before the path.
const PATH_OFFSET: usize = 2;

/// A `sockaddr_un` longer than the struct, as the macOS kernel accepts it.
pub struct LongAddress {
    bytes: [u8; libc::SOCK_MAXADDRLEN as usize],
    len: libc::socklen_t,
}

/// The hand-built address for `path`, or `None` when the path fits `sun_path`.
pub fn long_address(path: &Path) -> io::Result<Option<LongAddress>> {
    let path = path.as_os_str().as_bytes();
    if path.len() <= SUN_PATH_MAX {
        return Ok(None);
    }
    let len = PATH_OFFSET + path.len() + 1;
    if len > libc::SOCK_MAXADDRLEN as usize || path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AF_UNIX path is longer than SOCK_MAXADDRLEN or contains a NUL byte",
        ));
    }
    let mut bytes = [0; libc::SOCK_MAXADDRLEN as usize];
    bytes[0] = len as u8;
    bytes[1] = libc::AF_UNIX as u8;
    bytes[PATH_OFFSET..PATH_OFFSET + path.len()].copy_from_slice(path);
    Ok(Some(LongAddress {
        bytes,
        len: len as libc::socklen_t,
    }))
}

pub fn bind(fd: RawFd, addr: &LongAddress) -> io::Result<()> {
    // SAFETY: `addr.bytes` holds `addr.len` initialized bytes of a sockaddr_un.
    match unsafe { libc::bind(fd, addr.bytes.as_ptr().cast(), addr.len) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

pub fn connect(fd: RawFd, addr: &LongAddress) -> io::Result<()> {
    // SAFETY: `addr.bytes` holds `addr.len` initialized bytes of a sockaddr_un.
    match unsafe { libc::connect(fd, addr.bytes.as_ptr().cast(), addr.len) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}

/// `UnixListener::bind`, for a path of any length up to `SOCK_MAXADDRLEN`.
pub fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    let Some(addr) = long_address(path)? else {
        return UnixListener::bind(path);
    };
    // SAFETY: a plain socket(2) call; the fd is owned by the listener below.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh socket that nothing else owns.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    // SAFETY: `fd` is valid; FD_CLOEXEC matches what std sets on its sockets.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    bind(fd, &addr)?;
    // SAFETY: `fd` is a bound stream socket.
    match unsafe { libc::listen(fd, 128) } {
        0 => Ok(listener),
        _ => Err(io::Error::last_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;

    #[test]
    fn a_path_longer_than_sun_path_binds_and_connects() {
        let dir = std::env::temp_dir().join(format!("krun-long-{}", std::process::id()));
        let deep = dir.join("d".repeat(120));
        std::fs::create_dir_all(&deep).unwrap();
        let path = deep.join("agent.sock");
        assert!(path.as_os_str().len() > SUN_PATH_MAX);

        let listener = bind_listener(&path).unwrap();
        // SAFETY: a plain socket(2) call; the stream below owns the fd.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut client = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        connect(client.as_raw_fd(), &long_address(&path).unwrap().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"ok").unwrap();
        let mut reply = [0; 2];
        server.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"ok");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_short_path_is_left_to_sockaddr_un() {
        assert!(long_address(Path::new("/tmp/agent.sock")).unwrap().is_none());
    }
}
