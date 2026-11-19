using System.Text;

namespace WifiRoamLog;

/// <summary>Last-resort error handling: log to the session folder (when logging) and to %AppData%\WifiRoamLog\errors.log, and show a friendly dialog instead of the .NET crash box.</summary>
internal static class CrashLog
{
    public static volatile string? SessionFolder;
    private static int _showing;

    public static void Install()
    {
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) => Handle(e.Exception, fatal: false);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => Handle(e.ExceptionObject as Exception ?? new Exception(e.ExceptionObject?.ToString()), fatal: e.IsTerminating);
        TaskScheduler.UnobservedTaskException += (_, e) => { Write(e.Exception); e.SetObserved(); };
    }

    public static string Write(Exception ex)
    {
        string text = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}{Environment.NewLine}{Environment.NewLine}";
        string main = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WifiRoamLog", "errors.log");
        foreach (var path in new[] { main, SessionFolder is { } f ? Path.Combine(f, "errors.log") : null })
        {
            if (path is null) continue;
            try { Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.AppendAllText(path, text, new UTF8Encoding(false)); } catch { }
        }
        return main;
    }

    private static void Handle(Exception ex, bool fatal)
    {
        string log = Write(ex);
        if (Interlocked.Exchange(ref _showing, 1) != 0) return;   // one dialog at a time, no dialog storms
        try
        {
            MessageBox.Show("Wi-Fi Roam Log hit an unexpected error" + (fatal ? " and has to close" : " but keeps running") + ".\r\n\r\n" + ex.Message +
                "\r\n\r\nLogging to the CSV files is not affected by display errors. Details were written to:\r\n" + log,
                "Wi-Fi Roam Log", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch { }
        finally { Interlocked.Exchange(ref _showing, 0); }
    }
}
