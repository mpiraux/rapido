#!/usr/bin/bash

ip netns add tcpls_server
ip netns add tcpls_client
ip link set tun1 netns tcpls_client
ip link set tun0 netns tcpls_server
ip netns exec tcpls_client ip link set tun1 up
ip netns exec tcpls_server ip link set tun0 up
ip netns exec tcpls_client ip addr add 10.0.0.2/24 dev tun1
ip netns exec tcpls_server ip addr add 10.0.0.1/24 dev tun0
