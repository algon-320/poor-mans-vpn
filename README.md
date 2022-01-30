
## Poor Man's VPN

A super naive, (possibly unreliable), VPN implementation.

### Try on Docker Containers

You can test the VPN on docker containers.
`up.sh` script builds the image automatically and launches containers.
`down.sh` script terminates the contianers.

Start containers:
```
$ sudo ./up.sh
```
and then attach the `server` container:
```
$ sudo docker attach server
# RUST_LOG=debug server
```
and attach the `net1-host` container:
```
$ sudo docker attach net1-host
# RUST_LOG=debug client
```
also, attach the `net2-host` container:
```
$ sudo docker attach net2-host
# RUST_LOG=debug client
```

Finally, `net1-host` and `net2-host` can communicate via `vpn0` interface.
```
$ sudo docker exec -it net1-host /bin/bash
# ip addr show dev vpn0 | awk '/inet/{print $2}'
10.20.30.2/24
# ping 10.20.30.3  # ping to net2-host
PING 10.20.30.3 (10.20.30.3): 56 data bytes
64 bytes from 10.20.30.3: seq=0 ttl=64 time=0.846 ms
64 bytes from 10.20.30.3: seq=1 ttl=64 time=1.250 ms
64 bytes from 10.20.30.3: seq=2 ttl=64 time=1.253 ms
^C
--- 10.20.30.3 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.846/1.116/1.253 ms
```
```
$ sudo docker exec -it net2-host /bin/bash
# ip addr show dev vpn0 | awk '/inet/{print $2}'
10.20.30.3/24
```

To clean up the containers, just run:
```
$ sudo ./down.sh
```

### Usage

1. Generate a key pair on the server host:
    ```
    [server] $ mkdir keys
    [server] $ ./genkey.sh > keys/privkey.der
    [server] $ ./pubkey.sh < keys/privkey.der > server_pubkey.der
    ```
2. Generate a pair of keys on a peer host:
    ```
    [peer1] $ mkdir keys
    [peer1] $ ./genkey.sh > keys/privkey.der
    [peer1] $ ./pubkey.sh < keys/privkey.der > peer1_pubkey.der
    [peer1] $ cp server_pukey.der keys/  # place the server public key under 'keys/'
    ```
2. Generate a pair of keys on another peer host as well:
    ```
    [peer2] $ mkdir keys
    [peer2] $ ./genkey.sh > keys/privkey.der
    [peer2] $ ./pubkey.sh < keys/privkey.der > peer2_pubkey.der
    [peer2] $ cp server_pukey.der keys/  # place the server public key under 'keys/'
    ```
3. Register peers' public key on the server:
    ```
    [server] $ cp peer1_pubkey.der keys/
    [server] $ cp peer2_pubkey.der keys/
    ```
4. Start a server process on the server host:
    ```
    [server] $ # edit server-config.toml
    [server] $ cargo run --bin server
    ```
5. Start a client process on the peer hosts:
    ```
    [peer1] $ # edit client-config.toml
    [peer1] $ cargo run --bin client
    ```
    ```
    [peer2] $ # edit client-config.toml
    [peer2] $ cargo run --bin client
    ```
6. Now two peers (and server) can communicate via `vpn0` interface.
    ```
    [peer1] $ ping 10.20.30.3  # ping-ing to peer2
    ```
    ```
    [peer2] $ ping 10.20.30.2  # ping-ing to peer1
    ```
