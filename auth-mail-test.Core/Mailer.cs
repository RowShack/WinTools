using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace AuthMailTest.Core;

/// <summary>Sends one real test email through MailKit. Only called after an explicit confirmation in the UI.</summary>
public static class Mailer
{
    public static async Task SendTestAsync(SmtpRequest req, string subject, string body, CancellationToken ct)
    {
        if (req.MailFrom.Length == 0 || req.RcptTo.Length == 0) throw new ArgumentException("Sender and recipient are required.");
        var msg = new MimeMessage();
        msg.From.Add(MailboxAddress.Parse(req.MailFrom));
        msg.To.Add(MailboxAddress.Parse(req.RcptTo));
        msg.Subject = subject;
        msg.Body = new TextPart("plain") { Text = body };

        using var client = new SmtpClient { Timeout = req.TimeoutSeconds * 1000, CheckCertificateRevocation = false };
        client.ServerCertificateValidationCallback = (_, _, _, errors) => req.IgnoreCertErrors || errors == System.Net.Security.SslPolicyErrors.None;
        var opt = req.Security switch
        {
            SmtpSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect,
            SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
            _ => SecureSocketOptions.None,
        };
        await client.ConnectAsync(req.Host, req.Port, opt, ct);
        if (req.User.Length > 0) await client.AuthenticateAsync(req.User, req.Password, ct);
        await client.SendAsync(new SendRequest(msg), ct);
        await client.DisconnectAsync(true, ct);
    }
}
