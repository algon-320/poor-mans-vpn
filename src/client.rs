use etherparse::Ipv4Header;
use poor_mans_vpn::{crypto, error, setup_tun, Channel, Message, SealedPacket};
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use error::{Error, Result};

const CONFIG_FILE: &str = "client-config.toml";

mod default_config {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    pub fn ipv4_addr_unspecified() -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }

    pub fn server_bind_port() -> u16 {
        31415
    }

    pub fn ifname() -> String {
        "vpn0".to_owned()
    }

    pub fn max_transmission_unit() -> u16 {
        1300
    }

    pub fn server_public_key() -> PathBuf {
        let mut p = PathBuf::new();
        p.push("keys");
        p.push("server_pubkey.der");
        p
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
    peer: PeerConfig,
    server: ServerConfig,
}

#[derive(Debug, serde::Deserialize)]
struct PeerConfig {
    /// The name of a network interface to be used.
    #[serde(default = "default_config::ifname")]
    ifname: String,

    /// The address to be assigned to the VPN interface.
    address: Ipv4Addr,

    /// The MTU value of the VPN interface.
    #[serde(default = "default_config::max_transmission_unit")]
    mtu: u16,

    /// A path to the public key of the server.
    #[serde(default = "default_config::private_key")]
    private_key: PathBuf,

    /// The binding address of the client UDP socket.
    #[serde(default = "default_config::ipv4_addr_unspecified")]
    bind_address: Ipv4Addr,

    /// The binding port of the client UDP socket.
    #[serde(default)] // 0
    bind_port: u16,
}

#[derive(Debug, serde::Deserialize)]
struct ServerConfig {
    /// The binding address of the server.
    bind_address: Ipv4Addr,

    /// The binding port of the server.
    #[serde(default = "default_config::server_bind_port")]
    port: u16,

    /// A path to the public key of the server.
    #[serde(default = "default_config::server_public_key")]
    public_key: PathBuf,
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
                log::error!("failed to parse {:?}", CONFIG_FILE);
                return Ok(());
            }
        }
    };
    log::debug!("config: {:#?}", config);

    let static_key_pair = crypto::StaticKeyPair::from_pkcs8(&config.peer.private_key)?;
    let server_pubkey = std::fs::read(&config.server.public_key)?;

    let iface = setup_tun(
        &config.peer.ifname,
        config.peer.address,
        24,
        config.peer.mtu,
    )?;
    let iface = Arc::new(iface);

    let mut channel = {
        let sock = UdpSocket::bind((config.peer.bind_address, config.peer.bind_port))?;

        // We focus on communicatating with the server
        sock.connect((config.server.bind_address, config.server.port))?;

        Channel::new(sock)
    };

    // Establish a connection
    let session_key = {
        let (priv_seed, pub_seed) = crypto::generate_seed_pair();
        let signed_seed = static_key_pair.sign(&pub_seed);

        let hello = Message::Hello {
            addr: config.peer.address,
            seed: signed_seed,
        };
        channel.send(&hello).expect("send hello");

        let msg = channel.recv().expect("recv or parse");
        match msg {
            Message::HelloReply { seed: server_seed } => {
                let server_seed = server_seed.open(&server_pubkey).expect("signature invalid");
                let key = crypto::SessionKey::client_derive(priv_seed, server_seed);
                log::info!("connection established!");
                key
            }
            _ => {
                panic!("unexpected message");
            }
        }
    };
    let session_key = Arc::new(Mutex::new(session_key));

    std::thread::spawn({
        let mut channel = channel.clone();
        move || loop {
            // FIXME: make `freq` configuarable
            let freq = std::time::Duration::from_secs(5);
            std::thread::sleep(freq);
            if let Err(err) = channel.send(&Message::HeartBeat) {
                print_error("heart beat", err);
            }
        }
    });

    std::thread::spawn({
        let iface = iface.clone();
        let mut channel = channel.clone();
        let session_key = session_key.clone();
        move || -> std::io::Result<()> {
            loop {
                let msg = match channel.recv() {
                    Err(err) => {
                        print_error("channel.recv", err);
                        continue;
                    }
                    Ok(msg) => msg,
                };

                match msg {
                    Message::Packet(sealed_packet) => {
                        let packet: Vec<u8> = {
                            let key = session_key.lock().expect("poisoned");
                            let aad = sealed_packet.addresses_as_bytes();
                            let mut content = sealed_packet.content;
                            match key.unseal(&aad, &mut content) {
                                Ok(p) => p,
                                Err(err) => {
                                    print_error("unseal", err);
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
                        log::debug!(
                            "receive {} bytes: {:?} --> {:?}",
                            packet.len(),
                            Ipv4Addr::from(ip_hdr.source),
                            Ipv4Addr::from(ip_hdr.destination),
                        );

                        iface.send(&packet)?;
                    }

                    Message::HeartBeat => {
                        log::trace!("HeartBeat from the server");
                    }

                    _ => {
                        log::error!("unexpected message");
                    }
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

        let mut sealed_packet = SealedPacket {
            source,
            destination,
            content: Vec::new(),
        };
        let mut key = session_key.lock().expect("poisoned");
        let aad = sealed_packet.addresses_as_bytes();
        sealed_packet.content = key.seal(&aad, packet.to_vec()).expect("Failed to encrypt");

        if let Err(err) = channel.send(&Message::Packet(sealed_packet)) {
            print_error("channel.send", err);
        }
    }
}
