# Morning notes — overnight build (started after you went to bed)

**Nothing has been pushed or released.** Everything is committed locally on `main` (run `git log --oneline`). CLAUDE.md says not to push without being asked.

## Done (each: Core library + xUnit tests + WinForms GUI + README + self-contained publish builds OK)

| App | Tests | Smoke-launched | Notes |
|-----|-------|----------------|-------|
| mtu-finder | 21 pass | yes + live ICMP test against 8.8.8.8 | |
| port-probe | 25 pass | yes | |
| auth-mail-test | 54 pass | yes | LDAP path has no live test (no LDAP server on this PC) |

## Questions for you

1. **mtu-finder** — Windows does not expose the next-hop MTU in "packet too big" replies (I tested), so it plain binary-searches. Fine? The optional TCP-based estimate (for ICMP-filtered paths) is **not built yet**; want it?
2. **auth-mail-test** — I used my own small raw SMTP client for the conversation/relay test (MailKit can't do MAIL FROM/RCPT TO + RSET without sending DATA); MailKit is used only to send the real test email. OK, or do you want MailKit throughout and drop the "stop before DATA" relay test?
3. **auth-mail-test / LDAP** — please try it against a real DC/LDAPS server when convenient; I could only unit-test the error decoding.
4. **Releases** — shall I push these and create GitHub releases (`mtu-finder-v0.1.0`, `port-probe-v0.1.0`, `auth-mail-test-v0.1.0`)? Each self-contained exe is ~115 MB; a framework-dependent build is also easy.
5. **Old dhcp-finder repo** — still need your yes to put a "moved to WinTools" note in its README and archive it.
6. **Persistent routes registry key** (your earlier question) — still unanswered; say the word and I'll check it.

(Apps below are appended as they get done.)
