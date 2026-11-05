using System.Text;

namespace MnMSniffer;

/// <summary>One decoded application message per line. Flushed on every line so a close keeps them.</summary>
sealed class ParsedWriter : ISink, IDisposable
{
    readonly StreamWriter _writer;
    int _logged;

    public ParsedWriter(string path)
    {
        var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read);
        _writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
        {
            AutoFlush = true
        };
    }

    public void Emit(AppPacket packet)
    {
        try
        {
            _writer.WriteLine(PacketJson.ToJson(packet));
        }
        catch (Exception)
        {
            if (Interlocked.Exchange(ref _logged, 1) == 0)
                Log.Warn("One decoded message could not be written. Capture continues.");
        }
    }

    public void Dispose() => _writer.Dispose();
}
