pub mod crypto;
pub mod error;

use error::{Error, Result};

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

fn run_command(cmd: &str, args: &[&str]) -> Result<()> {
    use std::process::Command;
    let cmd_status = Command::new(cmd).args(args).status()?;
    if cmd_status.success() {
        Ok(())
    } else {
        Err(Error::Setup {
            msg: format!("command: {} args: {}", cmd, args.join(" ")),
        })
    }
}

/// Opens a tun device named <ifname>, and configures it with the "ip" utility.
pub fn setup_tun(
    ifname: &str,
    addr: Ipv4Addr,
    netmask_bit: u8,
    mtu: u16,
) -> Result<tun_tap::Iface> {
    let iface = tun_tap::Iface::without_packet_info(ifname, tun_tap::Mode::Tun)?;

    run_command("ip", &["link", "set", "up", "dev", ifname])?;

    let mtu = mtu.to_string();
    run_command("ip", &["link", "set", "mtu", &mtu, "dev", ifname])?;

    let addr = format!("{}/{}", addr, netmask_bit);
    run_command("ip", &["addr", "add", &addr, "dev", ifname])?;

    Ok(iface)
}

/// A message of the protocol.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// The first message to establish a connection (from a peer to the server).
    Hello {
        addr: Ipv4Addr,
        seed: crypto::Signed<crypto::PubSeed>,
    },

    /// The second message to establish a connection (from the server to a peer).
    HelloReply {
        seed: crypto::Signed<crypto::PubSeed>,
    },

    /// A message to keep the connection, primarily for preserving NAPT table.
    HeartBeat,

    /// Contains encrypted IP packet.
    Packet(SealedPacket),
}

/// A wrapper around `UdpSocket` for easily sending/receiving `Message`s through the socket.
#[derive(Clone)]
pub struct Channel {
    sock: Arc<UdpSocket>,
    buf: Vec<u8>,
}
impl Channel {
    pub fn new(sock: UdpSocket) -> Self {
        Self {
            sock: Arc::new(sock),
            buf: vec![0; 4096],
        }
    }

    pub fn recv(&mut self) -> Result<Message> {
        let nb = self.sock.recv(&mut self.buf[..])?;
        let slice = &self.buf[..nb];
        let msg: Message = bincode::deserialize(slice).map_err(|_| error::Error::BrokenMessage)?;
        Ok(msg)
    }

    pub fn recv_from(&mut self) -> Result<(Message, SocketAddr)> {
        let (nb, from) = self.sock.recv_from(&mut self.buf[..])?;
        let slice = &self.buf[..nb];
        let msg: Message = bincode::deserialize(slice).map_err(|_| error::Error::BrokenMessage)?;
        Ok((msg, from))
    }

    pub fn send(&mut self, msg: &Message) -> Result<()> {
        let msg = bincode::serialize(msg).expect("invalid msg"); // TODO: reduce heap allocation
        self.sock.send(&msg[..])?;
        Ok(())
    }

    pub fn send_to(&mut self, msg: &Message, addr: SocketAddr) -> Result<()> {
        let msg = bincode::serialize(msg).expect("invalid msg"); // FIXME: reduce heap allocation
        self.sock.send_to(&msg[..], addr)?;
        Ok(())
    }
}

/// An encrypted IP packet.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct SealedPacket {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub content: Vec<u8>,
}

impl SealedPacket {
    /// Returns an bytes representation of the source and destination addresses.
    pub fn addresses_as_bytes(&self) -> [u8; 8] {
        let s = self.source.octets();
        let d = self.destination.octets();
        [s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3]]
    }
}
