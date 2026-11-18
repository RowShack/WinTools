# WinTools

Small, single-purpose Windows utilities. Each app lives in its own folder and is released separately (tags are `<app>-vX.Y.Z`).

| App | What it does |
|-----|--------------|
| [dhcp-finder](dhcp-finder) | Finds every DHCP server reachable from your adapters — spot rogue DHCP servers |
| [win-route-edit](win-route-edit) | View, add and delete IPv4 and IPv6 routes, with persistent routes and routing profiles |
| [mtu-finder](mtu-finder) | Finds the real path MTU to a destination and suggests an MSS clamp |
| [port-probe](port-probe) | Listener + prober that proves firewall rules work end to end; TCP/UDP states explained, TLS quick check |
| [auth-mail-test](auth-mail-test) | LDAP/LDAPS and SMTP testers with plain-English error explanations |
| [pktmon-gui](pktmon-gui) | GUI for the built-in Packet Monitor: filters, pcapng export, drops view (needs admin) |
| [snmp-live-graph](snmp-live-graph) | Live per-interface bandwidth graphs over SNMP v2c/v3, no server needed |
| [radius-tester](radius-tester) | RADIUS client for testing servers and NAS setups: PAP/CHAP/MS-CHAPv2, MFA challenge, accounting, RadSec |
| [forti-flow](forti-flow) | Paste FortiGate `diagnose debug flow` output, get a step-by-step explanation per packet with verdicts, plus a debug command generator |

Downloads are on the [Releases](../../releases) page. Building needs the .NET 10 SDK; see each app's README.
