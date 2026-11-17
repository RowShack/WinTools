# Win-Route-Edit

A small Windows GUI for viewing and editing the IPv4 and IPv6 routing tables — handy when troubleshooting, or when you change routes a lot.

## Features

- Separate IPv4 and IPv6 tabs showing the live routing table (destination, gateway, interface, route/interface/total metric, origin), sortable and filterable
- Add and delete routes, with validation (CIDR or dotted mask, host-bit check, gateway check)
- **Persistent routes** — tick "Persistent" and the route survives a reboot. Saved-but-inactive persistent routes (e.g. adapter is down) are shown greyed out
- **Route profiles** — named sets of routes you can Apply or Remove in one click (e.g. "Office VPN", "Lab network"). Create them in *Manage…*, or right-click rows in the table → *Add selected routes to profile…*
- Default route is shown in bold; deleting it asks for extra confirmation
- Profiles are stored in `%AppData%\WinTools\Win-Route-Edit\profiles.json`

## Running

Viewing works as a normal user. Changing routes needs administrator rights — if you start it unelevated, a banner offers *Restart as administrator*.

## Build

Requires the .NET 10 SDK.

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish
```

Use `--self-contained false` for a small build that needs the .NET 10 Desktop Runtime.

## How it works

Routes are read and changed with PowerShell's `Get-NetRoute` / `New-NetRoute` / `Remove-NetRoute` (active store, plus the persistent store for persistent routes). Every value passed to PowerShell is parsed and validated first.

## Notes

- IPv6 link-local zone IDs (`fe80::1%5`) are not accepted; pick the interface in the dialog instead.
- Windows-owned routes (origin "Local", e.g. on-link and broadcast entries) are managed by the OS and may be refused or re-created if deleted.
- Be careful with the default route (`0.0.0.0/0`) — removing it can cut off network access.
