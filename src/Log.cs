namespace MnMSniffer;

static class Log
{
    static readonly object Gate = new();
    static string? _path;

    public static void Init(string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        lock (Gate) _path = path;
    }

    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message) => Write("ERROR", message);

    static void Write(string level, string message)
    {
        var line = $"{DateTime.UtcNow:O} [{level}] {message}";
        lock (Gate)
        {
            Console.WriteLine(line);
            if (_path == null) return;
            try { File.AppendAllText(_path, line + Environment.NewLine); }
            catch (Exception) { /* logging must not stop capture */ }
        }
    }
}
