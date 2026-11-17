# MTU Finder

Finds the real path MTU to a destination and suggests a TCP MSS clamp — useful for VPN/IPsec, PPPoE and GRE problems.

![screenshot placeholder](docs/screenshot.png)

## How it works

It sends ICMP echo requests with a growing/shrinking payload, with **Don't Fragment** set for IPv4, and binary-searches the largest size that gets an answer. Each size is tried several times so ordinary packet loss isn't mistaken for an MTU limit.

Result: largest working payload, **path MTU** (payload + 28 for IPv4, + 48 for IPv6), **suggested MSS** (MTU − 40 / − 60) and the local interface MTU for comparison.

## Features

- IPv4 or IPv6 (or automatic), choice of source interface
- Probe log showing every attempt (size, success / packet-too-big / timeout)
- Says "No reply — MTU can't be measured" when ICMP is blocked, instead of reporting a wrong number
- Warns when oversized packets are silently dropped (PMTUD black hole) rather than answered with "packet too big"
- Batch tab: list of targets → results table, export CSV, copy table
- Reference panel of common MTUs and tunnel overheads
- Copy result / export log

## Requirements & usage

- Windows 10/11, no admin rights needed (uses the Windows ICMP API, no driver)
- Type a host or IP, press **Find MTU**

## Notes

- Windows does not tell us the next-hop MTU in "packet too big" replies, so the search is a plain binary search (about 8–11 probes).
- IPv6 routers never fragment, so IPv6 uses the "packet too big" reply instead of the DF bit.
- Run `WINTOOLS_LIVE=1 dotnet test` to include the manual live-network smoke test.

## Build

Requires the .NET 10 SDK.

```bash
dotnet test mtu-finder.Tests
dotnet publish mtu-finder -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o mtu-finder/publish
```
