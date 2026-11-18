using System.Text;
using RadiusTester.Core;

namespace RadiusTester.Tests;

public class ClientTests
{
    private const string Secret = "testing123";

    private static ServerProfile Profile(FakeRadiusServer s, string? secret = null) => new()
    {
        Host = "127.0.0.1", AuthPort = s.Port, AcctPort = s.Port, Secret = secret ?? Secret, TimeoutSeconds = 0.4, Retries = 2, NasIp = "10.1.2.3",
    };

    private static Task<AuthSession> Auth(RadiusClient c, AuthMethod m, string user = "alice", string pw = "pa55word", Func<ChallengePrompt, CancellationToken, Task<string?>>? chal = null) =>
        c.AuthenticateAsync(new AuthRequest { UserName = user, Password = pw, Method = m }, chal, null, CancellationToken.None);

    [Fact]
    public async Task Pap_accept_end_to_end_with_all_checks()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => srv.UserPassword(req) == "pa55word"
            ? srv.Reply(RadiusCode.AccessAccept, req, [RadiusAttribute.Text(Attr.ReplyMessage, "welcome"), RadiusAttribute.Text(Attr.Class, "grp")])
            : srv.Reply(RadiusCode.AccessReject, req);
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.Accept, ex.Verdict);
        Assert.True(ex.ResponseAuthenticatorValid);
        Assert.True(ex.ReplyHasMessageAuthenticator);
        Assert.True(ex.MessageAuthenticatorValid);
        Assert.Equal("welcome", ex.ReplyMessage);
        Assert.Equal(1, ex.Attempts);
        Assert.True(ex.Rtt > TimeSpan.Zero);
        // request: Message-Authenticator is the first attribute and verifies at the server
        var (req0, bytes0) = srv.Received[0];
        Assert.Equal(Attr.MessageAuthenticator, req0.Attributes[0].Type);
        Assert.True(RadiusCrypto.VerifyMessageAuthenticator(bytes0, Encoding.UTF8.GetBytes(Secret)));
        Assert.Equal("alice", Encoding.UTF8.GetString(req0.Find(Attr.UserName)!.Value));
        Assert.Equal([10, 1, 2, 3], req0.Find(Attr.NasIpAddress)!.Value);
    }

    [Fact]
    public async Task Wrong_password_gives_reject_with_hints_and_reply_message()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => srv.Reply(RadiusCode.AccessReject, req, [RadiusAttribute.Text(Attr.ReplyMessage, "Bad credentials")]);
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.Reject, ex.Verdict);
        Assert.Contains(ex.Hints, h => h.Contains("Bad credentials"));
        Assert.Contains(ex.Hints, h => h.Contains("PAP"));
    }

    [Fact]
    public async Task Silent_server_times_out_after_retries_with_wrong_secret_hint()
    {
        using var srv = new FakeRadiusServer(Secret);   // handler returns null: never answers
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.NoReply, ex.Verdict);
        Assert.Equal(3, ex.Attempts);            // 1 + 2 retries
        await Task.Delay(50);
        Assert.Equal(3, srv.Received.Count);
        Assert.Contains(ex.Hints, h => h.Contains("shared secret"));
        Assert.Contains(ex.Hints, h => h.Contains("registered as a RADIUS client"));
        Assert.Contains(ex.Hints, h => h.Contains("firewall"));
        // retransmissions are byte-identical (same id and authenticator)
        Assert.Equal(srv.Received[0].Bytes, srv.Received[2].Bytes);
    }

    [Fact]
    public async Task Retransmission_recovers_when_first_packets_are_dropped()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, n) => n < 3 ? null : srv.Reply(RadiusCode.AccessAccept, req);
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.Accept, ex.Verdict);
        Assert.Equal(3, ex.Attempts);
    }

    [Fact]
    public async Task Server_with_different_secret_yields_invalid_reply_not_accept()
    {
        using var srv = new FakeRadiusServer("another-secret");
        srv.Handler = (req, _, _) => srv.Reply(RadiusCode.AccessAccept, req);
        var ex = (await Auth(new RadiusClient(Profile(srv, Secret)), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.BadReply, ex.Verdict);
        Assert.False(ex.ResponseAuthenticatorValid);
        Assert.False(ex.Trusted);
        Assert.Contains(ex.Hints, h => h.Contains("Response Authenticator") && h.Contains("shared secret"));
    }

    [Fact]
    public async Task Tampered_message_authenticator_in_reply_is_detected()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) =>
        {
            var r = srv.Reply(RadiusCode.AccessAccept, req);
            r[RadiusPacket.FindAttributeOffset(r, Attr.MessageAuthenticator) + 2] ^= 0xFF;   // corrupt MA, then re-sign the header so only MA is wrong
            RadiusCrypto.ResponseAuthenticator(r, req.Authenticator, Encoding.UTF8.GetBytes(Secret)).CopyTo(r, 4);
            return r;
        };
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap)).Last!;
        Assert.True(ex.ResponseAuthenticatorValid);
        Assert.False(ex.MessageAuthenticatorValid);
        Assert.Equal(Verdict.BadReply, ex.Verdict);
    }

    [Fact]
    public async Task Missing_message_authenticator_in_reply_is_noted_and_toggle_off_skips_it()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => srv.Reply(RadiusCode.AccessAccept, req, messageAuth: false);
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.Accept, ex.Verdict);
        Assert.Contains(ex.Hints, h => h.Contains("BlastRADIUS"));

        var legacy = Profile(srv); legacy.SendMessageAuthenticator = false;
        var ex2 = (await Auth(new RadiusClient(legacy), AuthMethod.Pap)).Last!;
        Assert.Equal(Verdict.Accept, ex2.Verdict);
        Assert.Null(srv.Received[^1].Packet.Find(Attr.MessageAuthenticator));
        Assert.DoesNotContain(ex2.Hints, h => h.Contains("BlastRADIUS (CVE-2024-3596) add"));
    }

    [Fact]
    public async Task Chap_request_is_verifiable_by_server()
    {
        using var srv = new FakeRadiusServer(Secret);
        bool ok = false;
        srv.Handler = (req, _, _) =>
        {
            var cp = req.Find(Attr.ChapPassword)!.Value; var ch = req.Find(Attr.ChapChallenge)!.Value;
            ok = RadiusCrypto.ChapPassword(cp[0], Encoding.UTF8.GetBytes("pa55word"), ch).SequenceEqual(cp);
            return srv.Reply(ok ? RadiusCode.AccessAccept : RadiusCode.AccessReject, req);
        };
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.Chap)).Last!;
        Assert.True(ok);
        Assert.Equal(Verdict.Accept, ex.Verdict);
    }

    private static byte[] ServerMsChapReply(FakeRadiusServer srv, RadiusPacket req, string password, bool honest = true)
    {
        var auth = RadiusClient.FindVendorAttribute(req, 311, 11)!;
        var resp = RadiusClient.FindVendorAttribute(req, 311, 25)!;
        var peer = resp[2..18]; var nt = resp[26..50];
        var expected = MsChapV2.NtResponse(auth, peer, req.Find(Attr.UserName) is { } u ? Encoding.UTF8.GetString(u.Value) : "", password);
        if (!expected.SequenceEqual(nt))
            return srv.Reply(RadiusCode.AccessReject, req, [RadiusAttribute.Vsa(311, 2, [.. Encoding.ASCII.GetBytes("\u0001E=691 R=1 V=3")])]);
        var s = honest ? MsChapV2.AuthenticatorResponse(password, nt, peer, auth, Encoding.UTF8.GetString(req.Find(Attr.UserName)!.Value)) : "S=" + new string('0', 40);
        return srv.Reply(RadiusCode.AccessAccept, req, [RadiusAttribute.Vsa(311, 26, [resp[0], .. Encoding.ASCII.GetBytes(s)])]);
    }

    [Fact]
    public async Task MsChapV2_accept_validates_mutual_authentication()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => ServerMsChapReply(srv, req, "pa55word");
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.MsChapV2)).Last!;
        Assert.Equal(Verdict.Accept, ex.Verdict);
        Assert.Contains(ex.Notes, n => n.Contains("mutual authentication OK"));
    }

    [Fact]
    public async Task MsChapV2_forged_success_is_flagged()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => ServerMsChapReply(srv, req, "pa55word", honest: false);
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.MsChapV2)).Last!;
        Assert.Contains(ex.Notes, n => n.Contains("FAILED mutual authentication"));
    }

    [Fact]
    public async Task MsChapV2_wrong_password_reject_decodes_E691()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => ServerMsChapReply(srv, req, "different");
        var ex = (await Auth(new RadiusClient(Profile(srv)), AuthMethod.MsChapV2)).Last!;
        Assert.Equal(Verdict.Reject, ex.Verdict);
        Assert.Contains(ex.Hints, h => h.Contains("E=691") && h.Contains("wrong user name or password"));
    }

    [Fact]
    public async Task Challenge_response_flow_echoes_state_and_sends_otp_as_pap()
    {
        using var srv = new FakeRadiusServer(Secret);
        var state = new byte[] { 1, 2, 3, 4, 0xAA };
        srv.Handler = (req, _, _) =>
        {
            var st = req.Find(Attr.State);
            if (st == null) return srv.Reply(RadiusCode.AccessChallenge, req, [RadiusAttribute.Text(Attr.ReplyMessage, "Enter your OTP"), new RadiusAttribute(Attr.State, state)]);
            return srv.Reply(st.Value.SequenceEqual(state) && srv.UserPassword(req) == "123456" ? RadiusCode.AccessAccept : RadiusCode.AccessReject, req);
        };
        string? prompted = null;
        var session = await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap, chal: (p, _) => { prompted = p.ReplyMessage; return Task.FromResult<string?>("123456"); });
        Assert.Equal("Enter your OTP", prompted);
        Assert.Equal(2, session.Exchanges.Count);
        Assert.Equal(Verdict.Challenge, session.Exchanges[0].Verdict);
        Assert.Equal(Verdict.Accept, session.Last!.Verdict);
        Assert.Equal(state, srv.Received[1].Packet.Find(Attr.State)!.Value);
        Assert.NotEqual(srv.Received[0].Packet.Identifier, srv.Received[1].Packet.Identifier);
    }

    [Fact]
    public async Task Challenge_can_be_cancelled_by_user()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => srv.Reply(RadiusCode.AccessChallenge, req, [new RadiusAttribute(Attr.State, [9])]);
        var session = await Auth(new RadiusClient(Profile(srv)), AuthMethod.Pap, chal: (_, _) => Task.FromResult<string?>(null));
        Assert.True(session.ChallengeAbandoned);
        Assert.Single(session.Exchanges);
    }

    [Fact]
    public async Task Accounting_start_interim_stop_carry_requested_attributes_and_valid_authenticator()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, bytes, _) =>
            RadiusCrypto.AccountingRequestAuthenticator(bytes, Encoding.UTF8.GetBytes(Secret)).SequenceEqual(req.Authenticator)
                ? srv.Reply(RadiusCode.AccountingResponse, req, messageAuth: false) : null;
        var c = new RadiusClient(Profile(srv));
        foreach (var t in new[] { AcctRequest.Start, AcctRequest.Interim, AcctRequest.Stop })
        {
            var ex = await c.AccountingAsync(new AcctRequest { StatusType = t, SessionId = "S-1", UserName = "alice", FramedIp = "192.0.2.55", Class = "0xCAFE", CallingStationId = "aa-bb-cc-dd-ee-ff", SessionTime = t == 1 ? null : 60 }, CancellationToken.None);
            Assert.Equal(Verdict.AccountingOk, ex.Verdict);
        }
        var start = srv.Received[0].Packet;
        Assert.Equal(RadiusCode.AccountingRequest, start.Code);
        Assert.Equal(1u, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(start.Find(Attr.AcctStatusType)!.Value));
        Assert.Equal("S-1", Encoding.UTF8.GetString(start.Find(Attr.AcctSessionId)!.Value));
        Assert.Equal([192, 0, 2, 55], start.Find(Attr.FramedIpAddress)!.Value);
        Assert.Equal([0xCA, 0xFE], start.Find(Attr.Class)!.Value);
        Assert.Equal("aa-bb-cc-dd-ee-ff", Encoding.UTF8.GetString(start.Find(Attr.CallingStationId)!.Value));
        Assert.Null(start.Find(Attr.AcctSessionTime));
        Assert.NotNull(srv.Received[2].Packet.Find(Attr.AcctSessionTime));
        Assert.Equal(3, srv.Received.Count);
    }

    [Fact]
    public async Task Status_server_ping_is_signed_and_reply_validated()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, bytes, _) => req.Code == RadiusCode.StatusServer && RadiusCrypto.VerifyMessageAuthenticator(bytes, Encoding.UTF8.GetBytes(Secret))
            ? srv.Reply(RadiusCode.AccessAccept, req) : null;
        var ex = await new RadiusClient(Profile(srv)).StatusServerAsync(CancellationToken.None);
        Assert.Equal(Verdict.StatusOk, ex.Verdict);
        Assert.True(ex.MessageAuthenticatorValid);
        Assert.Equal(Attr.MessageAuthenticator, srv.Received[0].Packet.Attributes[0].Type);

        var wrong = await new RadiusClient(Profile(srv, "nope")).StatusServerAsync(CancellationToken.None);
        Assert.Equal(Verdict.NoReply, wrong.Verdict);
    }

    [Fact]
    public async Task Custom_and_vendor_attributes_are_sent()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, _) => srv.Reply(RadiusCode.AccessAccept, req);
        var dict = RadiusDictionary.LoadBuiltIn();
        var req = new AuthRequest { UserName = "u", Password = "p", Extra = [dict.Encode("Calling-Station-Id", "00-11-22-33-44-55"), dict.Encode("Fortinet-Group-Name", "VPN-Users"), dict.Encode("Service-Type", "Framed-User")] };
        await new RadiusClient(Profile(srv)).AuthenticateAsync(req, null, null, CancellationToken.None);
        var got = srv.Received[0].Packet;
        Assert.Equal("00-11-22-33-44-55", Encoding.UTF8.GetString(got.Find(Attr.CallingStationId)!.Value));
        Assert.Equal("VPN-Users", Encoding.UTF8.GetString(RadiusClient.FindVendorAttribute(got, 12356, 1)!));
        Assert.Equal([0, 0, 0, 2], got.Find(Attr.ServiceType)!.Value);
    }

    // ---------------- EAP-MD5 ----------------

    [Fact]
    public async Task Eap_md5_full_exchange()
    {
        using var srv = new FakeRadiusServer(Secret);
        var challenge = Enumerable.Range(0, 16).Select(i => (byte)(i * 7)).ToArray();
        var state = new byte[] { 0x55, 0x66 };
        srv.Handler = (req, bytes, _) =>
        {
            Assert.True(RadiusCrypto.VerifyMessageAuthenticator(bytes, Encoding.UTF8.GetBytes(Secret)));   // mandatory with EAP
            var eap = EapPacket.Parse(RadiusClient.ReadEapMessage(req)!);
            if (eap.Type == EapPacket.TypeIdentity)
            {
                var chal = new EapPacket(EapPacket.Request, 5, EapPacket.TypeMd5, [16, .. challenge]).Encode();
                return srv.Reply(RadiusCode.AccessChallenge, req, [new RadiusAttribute(Attr.EapMessage, chal), new RadiusAttribute(Attr.State, state)]);
            }
            bool ok = eap.Type == EapPacket.TypeMd5 && eap.Id == 5 && eap.Data[1..].SequenceEqual(EapMd5Method.ResponseValue(5, "pa55word", challenge))
                && req.Find(Attr.State)!.Value.SequenceEqual(state);
            var final = new EapPacket(ok ? EapPacket.Success : EapPacket.Failure, 5, 0, []).Encode();
            return srv.Reply(ok ? RadiusCode.AccessAccept : RadiusCode.AccessReject, req, [new RadiusAttribute(Attr.EapMessage, final)]);
        };
        var prof = Profile(srv); prof.SendMessageAuthenticator = false;   // EAP forces it anyway
        var s = await Auth(new RadiusClient(prof), AuthMethod.EapMd5);
        Assert.Equal(2, s.Exchanges.Count);
        Assert.Equal(Verdict.Accept, s.Last!.Verdict);
        Assert.Contains(s.Last.Notes, n => n.Contains("Success"));

        var bad = await Auth(new RadiusClient(prof), AuthMethod.EapMd5, pw: "wrong");
        Assert.Equal(Verdict.Reject, bad.Last!.Verdict);
    }

    [Fact]
    public async Task Eap_unsupported_method_is_nakked_then_reported()
    {
        using var srv = new FakeRadiusServer(Secret);
        int step = 0;
        srv.Handler = (req, _, _) =>
        {
            step++;
            var eap = EapPacket.Parse(RadiusClient.ReadEapMessage(req)!);
            var next = step == 1 ? new EapPacket(EapPacket.Request, 2, 25, [0x20]) : new EapPacket(EapPacket.Request, 3, 25, [0x20]);   // PEAP start, twice
            Assert.True(step != 2 || (eap.Type == EapPacket.TypeNak && eap.Data[0] == EapPacket.TypeMd5));
            return srv.Reply(RadiusCode.AccessChallenge, req, [new RadiusAttribute(Attr.EapMessage, next.Encode()), new RadiusAttribute(Attr.State, [1])]);
        };
        var s = await Auth(new RadiusClient(Profile(srv)), AuthMethod.EapMd5);
        Assert.Equal(2, s.Exchanges.Count);
        Assert.Contains(s.Last!.Notes, n => n.Contains("PEAP") && n.Contains("not implement"));
    }

    // ---------------- load test ----------------

    [Fact]
    public async Task Load_test_counts_results_and_latency()
    {
        using var srv = new FakeRadiusServer(Secret);
        srv.Handler = (req, _, n) => n % 5 == 0 ? null : srv.Reply(n % 5 == 1 ? RadiusCode.AccessReject : RadiusCode.AccessAccept, req);
        var prof = Profile(srv); prof.TimeoutSeconds = 0.3;
        var r = await LoadTest.RunAsync(prof, new AuthRequest { UserName = "u", Password = "p" }, 40, 400, false, null, CancellationToken.None);
        Assert.Equal(40, r.Sent);
        Assert.Equal(40, r.Accepted + r.Rejected + r.NoReply + r.Errors + r.Challenged);
        Assert.True(r.Accepted > 0 && r.NoReply > 0 && r.Rejected > 0);
        Assert.True(r.P50Ms > 0 && r.P99Ms >= r.P50Ms && r.MaxMs >= r.P99Ms);
    }

    [Fact]
    public void Percentiles_use_nearest_rank()
    {
        var s = Enumerable.Range(1, 100).Select(i => (double)i).ToList();
        Assert.Equal(50, LoadTest.Percentile(s, 50));
        Assert.Equal(95, LoadTest.Percentile(s, 95));
        Assert.Equal(99, LoadTest.Percentile(s, 99));
        Assert.Equal(100, LoadTest.Percentile(s, 100));
        Assert.Equal(0, LoadTest.Percentile([], 50));
        var r = LoadTest.Summarize(Enumerable.Range(1, 10).Select(i => (Verdict.Accept, (double)i)).Append((Verdict.NoReply, 0)), 2);
        Assert.Equal(11, r.Sent); Assert.Equal(1, r.NoReply); Assert.Equal(9, r.P90Ms); Assert.Equal(5.5, r.AchievedRate);
    }

    [Fact]
    public async Task Cancel_stops_a_pending_exchange()
    {
        using var srv = new FakeRadiusServer(Secret);
        var prof = Profile(srv); prof.TimeoutSeconds = 5;
        using var cts = new CancellationTokenSource(150);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new RadiusClient(prof).AuthenticateAsync(new AuthRequest { UserName = "u", Password = "p" }, null, null, cts.Token));
    }

    [Fact]
    public async Task Icmp_port_unreachable_is_reported_as_network_error()
    {
        int port; using (var tmp = new FakeRadiusServer("x")) port = tmp.Port;   // port now closed
        var prof = new ServerProfile { Host = "127.0.0.1", AuthPort = port, Secret = Secret, TimeoutSeconds = 1, Retries = 0 };
        var ex = (await new RadiusClient(prof).AuthenticateAsync(new AuthRequest { UserName = "u", Password = "p" }, null, null, CancellationToken.None)).Last!;
        Assert.True(ex.Verdict is Verdict.NetworkError or Verdict.NoReply);
        if (ex.Verdict == Verdict.NetworkError) Assert.Contains("ICMP", ex.Error);
    }
}
