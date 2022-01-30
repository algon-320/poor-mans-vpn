#!/bin/bash

IMAGE_NAME="poor-mans-vpn"
(docker images | grep "$IMAGE_NAME") || \
    docker build . -t "$IMAGE_NAME"

function docker-pid() {
    docker inspect --format '{{.State.Pid}}' $@
}

function run-container() {
    name=$1
    docker run --privileged \
        --name "$name" \
        --rm -itd --net=none -v "$PWD/shared:/root/shared" \
        "$IMAGE_NAME" /bin/bash
}

## Configure router and server

run-container 'net1-router'
run-container 'net2-router'
run-container 'server'

ip link add 'net1_to_br' type veth peer name 'br_to_net1'
ip link set up dev 'br_to_net1'
ip link set netns $(docker-pid 'net1-router') dev 'net1_to_br'
docker exec 'net1-router' ip link set up dev 'net1_to_br'
docker exec 'net1-router' ip addr add '10.255.0.1/16' dev 'net1_to_br'
docker exec 'net1-router' ip route add '0.0.0.0/0' via '10.255.0.0' dev 'net1_to_br'

ip link add 'net2_to_br' type veth peer name 'br_to_net2'
ip link set up dev 'br_to_net2'
ip link set netns $(docker-pid 'net2-router') dev 'net2_to_br'
docker exec 'net2-router' ip link set up dev 'net2_to_br'
docker exec 'net2-router' ip addr add '10.255.0.2/16' dev 'net2_to_br'
docker exec 'net2-router' ip route add '0.0.0.0/0' via '10.255.0.0' dev 'net2_to_br'

ip link add 'server_to_br' type veth peer name 'br_to_server'
ip link set up dev 'br_to_server'
ip link set netns $(docker-pid 'server') dev 'server_to_br'
docker exec 'server' ip link set up dev 'server_to_br'
docker exec 'server' ip addr add '10.255.0.3/16' dev 'server_to_br'
docker exec 'server' ip route add '0.0.0.0/0' via '10.255.0.0' dev 'server_to_br'

ip link add 'container-br' type bridge
ip link set master 'container-br' dev 'br_to_net1'
ip link set master 'container-br' dev 'br_to_net2'
ip link set master 'container-br' dev 'br_to_server'
ip link set up dev 'container-br'
ip addr add '10.255.0.0/16' dev 'container-br'

iptables -t filter -A FORWARD -o 'container-br' -j ACCEPT
iptables -t filter -A FORWARD -i 'container-br' ! -o 'container-br' -j ACCEPT
iptables -t nat -A POSTROUTING ! -o 'container-br' -s '10.255.0.0/16' -j MASQUERADE

echo 1 > /proc/sys/net/ipv4/ip_forward

## Add hosts to each network

run-container 'net1-host'
run-container 'net2-host'

ip link add net1_h_to_r type veth peer name 'net1_r_to_h'
ip link set netns $(docker-pid 'net1-router') dev 'net1_r_to_h'
docker exec 'net1-router' ip link set up dev 'net1_r_to_h'
docker exec 'net1-router' ip addr add '10.1.0.1/16' dev 'net1_r_to_h'
docker exec 'net1-router' iptables -t nat -A POSTROUTING -s '10.1.0.0/16' -o 'net1_to_br' -j MASQUERADE

ip link set netns $(docker-pid 'net1-host') dev 'net1_h_to_r'
docker exec 'net1-host' ip link set up dev 'net1_h_to_r'
docker exec 'net1-host' ip addr add '10.1.0.2/16' dev 'net1_h_to_r'
docker exec 'net1-host' ip route add '0.0.0.0/0' via '10.1.0.1' dev 'net1_h_to_r'

ip link add 'net2_h_to_r' type veth peer name 'net2_r_to_h'
ip link set netns $(docker-pid 'net2-router') dev 'net2_r_to_h'
docker exec 'net2-router' ip link set up dev 'net2_r_to_h'
docker exec 'net2-router' ip addr add '10.2.0.1/16' dev 'net2_r_to_h'
docker exec 'net2-router' iptables -t nat -A POSTROUTING -s '10.2.0.0/16' -o 'net2_to_br' -j MASQUERADE

ip link set netns $(docker-pid 'net2-host') dev 'net2_h_to_r'
docker exec 'net2-host' ip link set up dev 'net2_h_to_r'
docker exec 'net2-host' ip addr add '10.2.0.2/16' dev 'net2_h_to_r'
docker exec 'net2-host' ip route add '0.0.0.0/0' via '10.2.0.1' dev 'net2_h_to_r'

## Generate keys

docker exec 'server' sh -c 'mkdir keys'
docker exec 'server' sh -c './genkey.sh > keys/privkey.der'
docker exec 'server' sh -c './pubkey.sh < keys/privkey.der > shared/server_pubkey.der'

docker exec 'net1-host' sh -c 'mkdir keys'
docker exec 'net1-host' sh -c './genkey.sh > keys/privkey.der'
docker exec 'net1-host' sh -c './pubkey.sh < keys/privkey.der > shared/peer1_pubkey.der'
docker exec 'net1-host' sh -c 'cp shared/server_pubkey.der keys/'

docker exec 'net2-host' sh -c 'mkdir keys'
docker exec 'net2-host' sh -c './genkey.sh > keys/privkey.der'
docker exec 'net2-host' sh -c './pubkey.sh < keys/privkey.der > shared/peer2_pubkey.der'
docker exec 'net2-host' sh -c 'cp shared/server_pubkey.der keys/'

docker exec 'server' bash -c 'cp shared/peer{1,2}_pubkey.der keys/'
docker exec 'server' sh -c 'rm shared/*.der'

docker exec 'net2-host' sh -c "sed -i 's/10.20.30.2/10.20.30.3/' client-config.toml"
