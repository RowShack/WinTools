# WinTools – project conventions

Repo RowShack/WinTools: a collection of small, portable Windows GUI tools for network/IT engineers. Existing apps: `dhcp-finder` and `win-route-edit` (.NET 10 WinForms). Each app is released separately with tags `<app>-vX.Y.Z`.

## Conventions for every new tool

- Before writing code, read `dhcp-finder` and `win-route-edit` and copy their structure: folder layout, GUI framework (WinForms), project settings, README style, build/publish setup. Do not introduce a different GUI framework without approval.
- Each tool lives in its own top-level folder with its own README (what it does, screenshot placeholder, requirements, usage, build).
- Ship as a single self-contained portable .exe (`dotnet publish`, self-contained, single-file). No installer, no services, no drivers unless the prompt says so.
- Admin rights: if a tool is useless without admin, add an app manifest requesting it. If it is partly useful without admin, run as a normal user and show the "Restart as administrator" banner (as win-route-edit does). Say which in the README.
- Never leave the system in a changed state: anything the tool turns on (captures, firewall rules, filters) must be cleaned up on exit and on crash recovery at next launch.
- Keep secrets (passwords, SNMP communities, RADIUS secrets) out of plain-text files: encrypt saved profiles with DPAPI (CurrentUser).
- Protocol/parsing logic goes in a separate class library with xUnit tests; keep the GUI thin. Layout for new apps: `<app>/` (GUI), `<app>.Core/` (logic), `<app>.Tests/` (xUnit). All projects are in the root `WinTools.slnx`. The two original apps stay single-project unless converted deliberately.
- Every action that takes time runs async with a Cancel button; the UI never freezes.
- Results can always be copied to the clipboard and exported (CSV/TXT, plus format-specific exports noted per tool).
- Update the root README's tool list when a tool is added.

## Workflow

For each new app: first propose a short plan (screens, classes, libraries with licences, risks) and wait for OK. Then build an MVP, then the extras. Run the tests and a publish build before saying it is done. Build apps one at a time, in the agreed order:

1. mtu-finder  2. port-probe  3. auth-mail-test  4. pktmon-gui  5. snmp-live-graph
6. radius-tester  7. forti-flow (needs sample files from the user)  8. host-top  9. wifi-roam-log

Specs for each app are in the user's `wintools-claude-code-prompts.md` (Downloads folder). Verify external tool flags (e.g. pktmon) against the real tool's help on this machine rather than from memory. Do not push or release without being asked.
