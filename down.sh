#!/bin/bash

docker stop "net1-router" "net1-host"
docker stop "net2-router" "net2-host"
docker stop "server"

ip link set down dev container-br
brctl delbr container-br

iptables -t filter -D FORWARD -o container-br -j ACCEPT
iptables -t filter -D FORWARD -i container-br ! -o container-br -j ACCEPT
iptables -t nat -D POSTROUTING ! -o container-br -s 10.255.0.0/16 -j MASQUERADE

(ip link | grep server_to_br) && ip link del server_to_br
(ip link | grep net1_to_br)   && ip link del net1_to_br
(ip link | grep net2_to_br)   && ip link del net2_to_br
(ip link | grep net1_h_to_r)  && ip link del net1_h_to_r
(ip link | grep net2_h_to_r)  && ip link del net2_h_to_r
