# Morning notes — overnight build (started after you went to bed)

**Nothing has been pushed or released.** Everything is committed locally on `main` (run `git log --oneline`). CLAUDE.md says not to push without being asked.

## Done (each: Core library + xUnit tests + WinForms GUI + README + self-contained publish builds OK)

| App | Tests | Smoke-launched | Notes |
|-----|-------|----------------|-------|
| mtu-finder | 21 pass | yes + live ICMP test against 8.8.8.8 | |
| port-probe | 25 pass | yes | |
| auth-mail-test | 54 pass | yes | LDAP path has no live test (no LDAP server on this PC) |
| snmp-live-graph | 29 pass | yes, plus a harness that rendered a live chart (screenshot checked) and ran from a single-file publish | v2c tested end to end against an in-process fake agent; **v3 untested** |
| pktmon-gui | 43 pass | yes (UI only — see below) | Needs admin; I could NOT run the real pktmon driver |

## Questions for you

1. **mtu-finder** — Windows does not expose the next-hop MTU in "packet too big" replies (I tested), so it plain binary-searches. Fine? The optional TCP-based estimate (for ICMP-filtered paths) is **not built yet**; want it?
2. **auth-mail-test** — I used my own small raw SMTP client for the conversation/relay test (MailKit can't do MAIL FROM/RCPT TO + RSET without sending DATA); MailKit is used only to send the real test email. OK, or do you want MailKit throughout and drop the "stop before DATA" relay test?
3. **auth-mail-test / LDAP** — please try it against a real DC/LDAPS server when convenient; I could only unit-test the error decoding.
4. **Releases** — shall I push these and create GitHub releases (`mtu-finder-v0.1.0`, `port-probe-v0.1.0`, `auth-mail-test-v0.1.0`)? Each self-contained exe is ~115 MB; a framework-dependent build is also easy.
5. **Old dhcp-finder repo** — still need your yes to put a "moved to WinTools" note in its README and archive it.
6. **Persistent routes registry key** (your earlier question) — still unanswered; say the word and I'll check it.

7. **pktmon-gui — please test elevated.** Every pktmon command returns "Access is denied" without admin, so I never saw the real output of `pktmon list --json`, `counters`, `status` or `etl2txt` on this build. The parsers are defensive and tested against sample text I wrote from memory — they may need adjusting. Specifically check: adapter list fills in, counters show numbers, Drops tab finds drops, leftover-capture detection at startup (it uses text heuristics on `pktmon status`). The exe uses a requireAdministrator manifest (UAC prompt on launch), so I only smoke-tested a non-elevated build.
8. **pktmon-gui** — optional de-duplication of multi-component captures is not built. Want it?

9. **snmp-live-graph — SNMPv3** is written but untested against a real device (my test agent is v2c only). Could you try it against one v3 device? Also not built yet: threshold lines, ad-hoc OID graphs and the interface up/down change log (all "extras" in your spec).
10. **Not started** (ran out of overnight runway, in your agreed order): radius-tester, forti-flow (needs your sanitised samples first — allowed+SNAT, denied by policy, RPF drop, IPsec, VIP/DNAT), host-top, wifi-roam-log. Want me to continue with radius-tester next?
11. **Repo housekeeping** — the root README table lists all new apps. Each app folder has `publish/` output (git-ignored) with a ~115 MB self-contained exe.

---
## Update (after your answers)

- Merged into `main`: mtu-finder TCP estimate, snmp-live-graph extras (thresholds, OID tiles, status log), and **radius-tester** (new). Whole solution builds; 275 tests pass.
- Decisions recorded: hold releases until you've tested; old dhcp-finder repo already deleted; keep the raw SMTP client; no pktmon de-duplication.
- Still needs YOU: test pktmon-gui elevated; SNMPv3 on a real device; LDAP against a real server; radius-tester against a real RADIUS server; the persistent-routes registry check (needs your admin approval at the PC).
- Not started: forti-flow (needs your samples), host-top, wifi-roam-log.
