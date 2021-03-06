use etherparse::Ipv4Header;
use poor_mans_vpn::{crypto, error, setup_tun, Channel, Message, SealedPacket};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use error::{Error, Result};

const CONFIG_FILE: &str = "server-config.toml";

mod default_config {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    pub fn ipv4_addr_unspecified() -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }

    pub fn bind_port() -> u16 {
        31415
    }

    pub fn ifname() -> String {
        "vpn0".to_owned()
    }

    pub fn max_transmission_unit() -> u16 {
        1300
    }

    pub fn server_address() -> Ipv4Addr {
        Ipv4Addr::new(10, 20, 30, 1)
    }

    pub fn private_key() -> PathBuf {
        let mut p = PathBuf::new();
        p.push("keys");
        p.push("privkey.der");
        p
    }
}

#[derive(Debug, serde::Deserialize)]
struct Config {
    server: ServerConfig,
    peers: Vec<PeerConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct ServerConfig {
    /// The binding address of the server.
    #[serde(default = "default_config::ipv4_addr_unspecified")]
    bind_address: Ipv4Addr,

    /// The binding port of the server.
    #[serde(default = "default_config::bind_port")]
    port: u16,

    /// The name of a network interface to be used.
    #[serde(default = "default_config::ifname")]
    ifname: String,

    /// The address to be assigned to the VPN interface.
    #[serde(default = "default_config::server_address")]
    address: Ipv4Addr,

    /// The MTU value of the VPN interface.
    #[serde(default = "default_config::max_transmission_unit")]
    mtu: u16,

    /// A path to the private key of the server.
    #[serde(default = "default_config::private_key")]
    private_key: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
struct PeerConfig {
    /// A address of the peer.
    address: Ipv4Addr,

    /// A path to the public key of the peer.
    public_key: PathBuf,
}

struct Peer {
    sock_addr: SocketAddr,
    session_key: crypto::SessionKey,
}

fn print_error<D: std::fmt::Display>(ctx: D, err: Error) {
    log::error!("{}: {}", ctx, err);
}

fn main() -> Result<()> {
    env_logger::init();

    let config: Config = {
        let config_toml = std::fs::read(CONFIG_FILE)?;
        match toml::from_slice(&config_toml) {
            Ok(conf) => conf,
            Err(_) => {
                log::error!("failed to parse {}", CONFIG_FILE);
                return Ok(());
            }
        }
    };
    log::debug!("config: {:#?}", config);

    let static_key_pair = crypto::StaticKeyPair::from_pkcs8(&config.server.private_key)?;

    let iface = setup_tun(
        &config.server.ifname,
        config.server.address,
        24,
        config.server.mtu,
    )?;
    let iface = Arc::new(iface);

    let sock = UdpSocket::bind((config.server.bind_address, config.server.port))?;
    let mut sock = Channel::new(sock);

    let peers: HashMap<Ipv4Addr, Peer> = HashMap::new();
    let peers = Arc::new(Mutex::new(peers));

    std::thread::spawn({
        let iface = iface.clone();
        let mut sock = sock.clone();
        let peers = peers.clone();
        move || -> std::io::Result<()> {
            loop {
                let (msg, src_addr) = match sock.recv_from() {
                    Err(err) => {
                        print_error("receive", err);
                        continue;
                    }
                    Ok(pair) => pair,
                };

                match msg {
                    Message::Hello {
                        addr,
                        seed: client_seed,
                    } => {
                        log::debug!("Hello message received from: {:?}", addr);

                        let peer_conf = config.peers.iter().find(|conf| conf.address == addr);
                        let pubkey = match peer_conf {
                            None => {
                                log::warn!("unknown peer: {:?}", addr);
                                continue;
                            }
                            Some(conf) => std::fs::read(&conf.public_key)?,
                        };

                        let client_seed = match client_seed.open(&pubkey) {
                            Err(err) => {
                                print_error("unseal", err);
                                continue;
                            }
                            Ok(seed) => seed,
                        };
                        let (priv_seed, pub_seed) = crypto::generate_seed_pair();
                        let session_key = crypto::SessionKey::server_derive(priv_seed, client_seed);

                        let mut peers = peers.lock().expect("poisoned");
                        peers.insert(
                            addr,
                            Peer {
                                sock_addr: src_addr,
                                session_key,
                            },
                        );

                        let signed_seed = static_key_pair.sign(&pub_seed);
                        let reply = Message::HelloReply { seed: signed_seed };
                        if let Err(err) = sock.send_to(&reply, src_addr) {
                            print_error("send", err);
                            continue;
                        }
                        log::info!("new connection with {:?} (socket: {:?})", addr, src_addr);
                    }

                    Message::HeartBeat => {
                        log::trace!("HeartBeat from {:?}", src_addr);
                        if let Err(err) = sock.send_to(&Message::HeartBeat, src_addr) {
                            print_error("send", err);
                            continue;
                        }
                    }

                    Message::Packet(mut sealed_packet) => {
                        let mut peers = peers.lock().expect("poisoned");
                        let packet: Vec<u8> = {
                            let src = sealed_packet.source;
                            let session_key = if let Some(peer) = peers.get(&src) {
                                &peer.session_key
                            } else {
                                log::warn!("unknown peer");
                                continue;
                            };

                            let aad = sealed_packet.addresses_as_bytes();
                            match session_key.unseal(&aad, &mut sealed_packet.content) {
                                Ok(p) => p,
                                Err(_) => {
                                    log::error!("failed to unseal a packet");
                                    continue;
                                }
                            }
                        };

                        let (ip_hdr, _payload) = match Ipv4Header::from_slice(&packet) {
                            Ok(hdr_payload) => hdr_payload,
                            Err(err) => {
                                log::debug!("ignored uninteresting packet: {}", err);
                                continue;
                            }
                        };

                        let source = Ipv4Addr::from(ip_hdr.source);
                        let destination = Ipv4Addr::from(ip_hdr.destination);

                        if destination == config.server.address {
                            log::debug!(
                                "receive {} bytes: {:?} --> {:?}",
                                packet.len(),
                                source,
                                destination,
                            );

                            iface.send(&packet)?;
                        } else {
                            if let Some(peer) = peers.get_mut(&destination) {
                                log::debug!(
                                    "forward {} bytes: {:?} --> {:?} ({:?})",
                                    packet.len(),
                                    source,
                                    destination,
                                    peer.sock_addr,
                                );
                                let mut sealed_packet = SealedPacket {
                                    source,
                                    destination,
                                    content: Vec::new(),
                                };
                                let aad = sealed_packet.addresses_as_bytes();
                                sealed_packet.content = peer
                                    .session_key
                                    .seal(&aad, packet.to_vec())
                                    .expect("Failed to encrypt");

                                let packet = Message::Packet(sealed_packet);
                                if let Err(err) = sock.send_to(&packet, peer.sock_addr) {
                                    print_error("send", err);
                                    continue;
                                }
                            } else {
                                // TODO: handle broadcast packets
                                log::warn!("unknown peer");
                            }
                        }
                    }

                    _ => log::error!("unexpected packet"),
                }
            }
        }
    });

    let mut buf = [0; 4096];
    loop {
        let nb = iface.recv(&mut buf[..])?;
        let packet = &buf[..nb];

        let (ip_hdr, _payload) = match Ipv4Header::from_slice(packet) {
            Ok(hdr_payload) => hdr_payload,
            Err(err) => {
                log::debug!("ignored uninteresting packet: {}", err);
                continue;
            }
        };

        let source = Ipv4Addr::from(ip_hdr.source);
        let destination = Ipv4Addr::from(ip_hdr.destination);
        log::debug!(
            "send    {} bytes: {:?} --> {:?}",
            packet.len(),
            source,
            destination,
        );

        if destination == config.server.address {
            // the packet is for the server host.
            continue;
        } else {
            let mut peers = peers.lock().expect("poisoned");
            if let Some(peer) = peers.get_mut(&destination) {
                let mut sealed_packet = SealedPacket {
                    source,
                    destination,
                    content: Vec::new(),
                };
                let aad = sealed_packet.addresses_as_bytes();
                sealed_packet.content = peer
                    .session_key
                    .seal(&aad, packet.to_vec())
                    .expect("Failed to encrypt");

                let packet = Message::Packet(sealed_packet);
                if let Err(err) = sock.send_to(&packet, peer.sock_addr) {
                    print_error("send", err);
                    continue;
                }
            } else {
                log::warn!("unknown peer");
            }
        }
    }
}
