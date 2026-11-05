using System.Diagnostics;

namespace MnMSniffer;

/// <summary>A running process whose name contains "MnM", excluding this program.</summary>
sealed class GameProcess : IDisposable
{
    public Process Process { get; }
    public string Name { get; }
    public int Pid { get; }
    public IReadOnlyList<string> Ignored { get; }

    GameProcess(Process process, IReadOnlyList<string> ignored)
    {
        Process = process;
        Name = process.ProcessName;
        Pid = process.Id;
        Ignored = ignored;
    }

    public static GameProcess? Find()
    {
        int self = Environment.ProcessId;
        using var selfProcess = Process.GetCurrentProcess();
        string selfName = selfProcess.ProcessName;
        var matches = new List<Process>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == self || process.ProcessName.Equals(selfName, StringComparison.OrdinalIgnoreCase))
                {
                    process.Dispose();
                    continue;
                }
                if (process.ProcessName.Contains("MnM", StringComparison.OrdinalIgnoreCase))
                    matches.Add(process);
                else
                    process.Dispose();
            }
            catch (Exception)
            {
                try { process.Dispose(); } catch (Exception) { }
            }
        }
        if (matches.Count == 0) return null;

        Process best = matches[0];
        int bestScore = Score(best);
        foreach (var process in matches)
        {
            int score = Score(process);
            if (score > bestScore)
            {
                best = process;
                bestScore = score;
            }
        }
        var ignored = new List<string>();
        foreach (var process in matches)
        {
            if (ReferenceEquals(process, best)) continue;
            ignored.Add($"{process.ProcessName} pid {process.Id}");
            process.Dispose();
        }
        return new GameProcess(best, ignored);
    }

    static int Score(Process process)
    {
        try { return UdpPorts.ForProcess(process.Id, out _).Length; }
        catch (Exception) { return 0; }
    }

    public void Dispose() => Process.Dispose();
}
