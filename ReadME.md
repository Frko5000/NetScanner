# 🔍 NetScanner

netscanner is a local network scanner built with node.js and vanilla js. pings your entire subnet, reads the arp table and tries to figure out what each device is.

## ✨ features

* detects all active devices on your local network.
* mac vendor lookup + hostname resolution.
* port probing to identify device roles (ssh, http, airplay, rdp etc).
* smart device classification — router, phone, printer, server, iot and more.
* clean dark ui with live scan status.

## 🛠️ tech stack

* node.js — zero external dependencies, pure stdlib.
* html5, css grid, vanilla js.

## 🚀 getting started

1. run the server:
```bash
node server.js
```

2. open `index.html` in your browser and hit **Scan Network**.

> scan takes ~30 seconds — pings all 254 hosts first, then enriches each device in parallel.

## ⚠️ notes

* needs to run on the same machine as your network interface.
* some devices wont appear if they block icmp pings.
* port probing is passive — only attempts a tcp handshake, nothing more.

claude is love :3