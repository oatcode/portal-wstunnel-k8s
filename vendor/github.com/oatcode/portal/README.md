# Portal

[![Go Reference](https://pkg.go.dev/badge/github.com/oatcode/portal.svg)](https://pkg.go.dev/github.com/oatcode/portal)
[![Release](https://img.shields.io/github/v/release/oatcode/portal)](https://github.com/oatcode/portal/releases)


A Go implementation of HTTP tunneling through a tunnel

## Overview

The main goal of this project is to provide access from cloud to on-prem without opening ports on-prem. This library provides a mechanism to build a 2-node HTTP tunnel.

The tunnel has two sides: client and server.
An on-prem application running tunnel client will connect to tunnel server running in cloud. Proxy port can be opened on cloud side to allow access to on-prem via HTTP tunnelling: <https://en.wikipedia.org/wiki/HTTP_tunnel>

This library only supports HTTPS tunneling that uses HTTP CONNECT to initiate connection.

## Install

    go get github.com/oatcode/portal

## Usage

Wrap the tunnel connection with Framer interface and use TunnelServe:

    coch := make(chan portal.ConnectOperation)
    portal.TunnelServe(ctx, framer, coch)

Framer interface is for reading and writing messages with boundaries (i.e. frame). The examples show a simple length/bytes and WebSocket framer.

coch is the channel to handle incoming proxy connection. Fill the ConnectOperation struct with net.Conn and proxy connect address. The examples illustrate how this is done with Go's http Hijack function.

## Examples

Included in the projects are example code to establish the tunnel and make HTTPS connection through it.

                   +---------+
                   | Cloud   |
                   | Client  |
                   +----+----+
                        |
                        |
                +-------v-------+
                | Proxy Server  |
                +---------------+
                | Tunnel Server |
                +-----+---^-----+
     Internet         |   |
    ------------------+---+--------------------
     On-prem          |   |
                +-----v---+-----+
                |               |
                | Tunnel Client |
                |               |
                +-------+-------+
                        |
                        |
                   +----v----+
                   | On-prem |
                   | Server  |
                   +---------+


To run the examples locally, create certificates for tunnel and https server:

    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -keyout tunnel-server.key -out tunnel-server.crt -subj "/C=US/CN=tunnel-server" -extensions SAN -config <(cat /etc/ssl/openssl.cnf  <(printf "\n[SAN]\nsubjectAltName=DNS:localhost\n"))
    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -keyout tunnel-client.key -out tunnel-client.crt -subj "/C=US/CN=tunnel-client" -extensions SAN -config <(cat /etc/ssl/openssl.cnf  <(printf "\n[SAN]\nsubjectAltName=DNS:localhost\n"))
    openssl req -x509 -nodes -newkey rsa:2048 -sha256 -keyout https-server.key -out https-server.crt -subj "/C=US/CN=https-server" -extensions SAN -config <(cat /etc/ssl/openssl.cnf  <(printf "\n[SAN]\nsubjectAltName=DNS:localhost\n"))

### Simple tunnel example
The example runs tunnel on port 10001 and proxy on port 10002:

    simple-tunnel -server -tunnelAddress :10001 -proxyAddress :10002 
    simple-tunnel -client -tunnelAddress localhost:10001

Run sample HTTPS server on port 10003 and client via proxy port 10002:

    sample-https-server -address :10003 -cert https-server.crt -key https-server.key
    sample-https-client --proxy http://localhost:10002 -url https://localhost:10003/test -trust https-server.crt 


### Websocket tunnel example
The example runs both websocket tunnel and proxy on port 10001. In addition, tunnel and proxy are protected by TLS and user/password:

    ws-tunnel -server -address :10001 -proxyBasicAuth app1:pw1 -tunnelBasicAuth tenant1:pw1 -cert tunnel-server.crt -key tunnel-server.key 
    ws-tunnel -client -address localhost:10001 -tunnelBasicAuth tenant1:pw1 -trust tunnel-server.crt

Run sample HTTPS server on port 10003 and client via proxy port 10001:

    sample-https-server -address :10003 -cert https-server.crt -key https-server.key
    sample-https-client --proxy https://app1:pw1@localhost:10001 -url https://localhost:10003/test -trust https-server.crt -trust tunnel-server.crt

## Other ways to set proxy

The sample-https-client sets proxy programmatically. But it can be set in other ways. For example:

- export https_proxy=[proxy-host]:[proxy-port]
- java -Dhttps.proxyHost=[proxy-host] -Dhttps.proxyPort=[proxy-port]
