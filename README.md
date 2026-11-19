# WinTools

Small, single-purpose Windows utilities. Each app lives in its own folder under [`apps/`](apps) and is released separately (tags are `<app>-vX.Y.Z`). Each is a single portable `.exe`: no installer, nothing left behind.

### Which download should I pick?

Every release has two `.exe` files. They contain the same app and behave identically; they differ only in whether the .NET runtime is bundled.

| File | Size | Needs | Pick it when |
|------|------|-------|--------------|
| `<App>-selfcontained.exe` | about 115-140 MB | nothing | **You just want it to work (recommended).** Runs on any 64-bit Windows 10/11, including servers and offline machines. It carries the .NET runtime inside, which is why it is large; the first start can take a second or two longer while it unpacks. |
| `<App>-framework-dependent.exe` | 0.3-22 MB | the [.NET 10 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/10.0) (x64) | You already have .NET 10, or you hand the tools to many people and want a tiny download. If the runtime is missing, Windows tells you and links to it; or install it with `winget install Microsoft.DotNet.DesktopRuntime.10`. |

Nothing needs installing either way, and nothing is left behind. The exes are not code-signed, so Windows SmartScreen may warn on first run (More info, then Run anyway). Tools that read network state or capture packets (pktmon-gui, host-top) ask for administrator rights.

### The tools

| App | What it does | Latest release |
|-----|--------------|----------------|
| 🔍 [dhcp-finder](apps/dhcp-finder) | Finds every DHCP server reachable from your adapters — spot rogue DHCP servers | [![dhcp-finder](https://img.shields.io/github/v/release/RowShack/WinTools?filter=dhcp-finder-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/dhcp-finder-v1.0.0) |
| 🛣️ [win-route-edit](apps/win-route-edit) | View, add and delete IPv4 and IPv6 routes, with persistent routes and routing profiles | [![win-route-edit](https://img.shields.io/github/v/release/RowShack/WinTools?filter=win-route-edit-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/win-route-edit-v0.1.0) |
| 📏 [mtu-finder](apps/mtu-finder) | Finds the real path MTU to a destination and suggests an MSS clamp | [![mtu-finder](https://img.shields.io/github/v/release/RowShack/WinTools?filter=mtu-finder-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/mtu-finder-v0.1.0) |
| 🚪 [port-probe](apps/port-probe) | Listener + prober that proves firewall rules work end to end; TCP/UDP states explained, TLS quick check | [![port-probe](https://img.shields.io/github/v/release/RowShack/WinTools?filter=port-probe-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/port-probe-v0.1.0) |
| 🔐 [auth-mail-test](apps/auth-mail-test) | LDAP/LDAPS and SMTP testers with plain-English error explanations | [![auth-mail-test](https://img.shields.io/github/v/release/RowShack/WinTools?filter=auth-mail-test-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/auth-mail-test-v0.1.0) |
| 📦 [pktmon-gui](apps/pktmon-gui) | GUI for the built-in Packet Monitor: filters, pcapng export, in-app packet viewer, drops view (needs admin) | [![pktmon-gui](https://img.shields.io/github/v/release/RowShack/WinTools?filter=pktmon-gui-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/pktmon-gui-v0.1.0) |
| 📈 [snmp-live-graph](apps/snmp-live-graph) | Live per-interface bandwidth graphs over SNMP v2c/v3, no server needed | [![snmp-live-graph](https://img.shields.io/github/v/release/RowShack/WinTools?filter=snmp-live-graph-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/snmp-live-graph-v0.1.0) |
| 🔑 [radius-tester](apps/radius-tester) | RADIUS client for testing servers and NAS setups: PAP/CHAP/MS-CHAPv2, MFA challenge, accounting, RadSec | [![radius-tester](https://img.shields.io/github/v/release/RowShack/WinTools?filter=radius-tester-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/radius-tester-v0.1.0) |
| 📊 [host-top](apps/host-top) | Live "who is using the bandwidth" view: throughput per remote host, process and connection via ETW (needs admin) | [![host-top](https://img.shields.io/github/v/release/RowShack/WinTools?filter=host-top-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/host-top-v0.1.0) |
| 📶 [wifi-roam-log](apps/wifi-roam-log) | Logs Wi-Fi signal, AP roams, disconnects, latency and loss over time (tray, CSV, charts) to explain "the Wi-Fi was slow at 10:15" | [![wifi-roam-log](https://img.shields.io/github/v/release/RowShack/WinTools?filter=wifi-roam-log-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/wifi-roam-log-v0.1.0) |
| 🔥 [forti-flow](apps/forti-flow) | Paste FortiGate `diagnose debug flow` output, get a step-by-step explanation per packet with verdicts, plus a debug command generator | [![forti-flow](https://img.shields.io/github/v/release/RowShack/WinTools?filter=forti-flow-v*&display_name=tag&label=latest)](https://github.com/RowShack/WinTools/releases/tag/forti-flow-v0.1.0) |

The **Latest release** badge shows the newest version of that app and links to its release page. "No matching releases found" means that app has not been released yet. All downloads are on the [Releases](../../releases) page. Building needs the .NET 10 SDK; see each app's README.
