using System.Diagnostics;
using SharpPcap;

namespace MnMSniffer;

static class Program
{
    static readonly ManualResetEventSlim Finished = new(false);
    static int _stop;

    static int Main(string[] args)
    {
        // Remember the folder the user started us from. A single-file exe must not switch to its extract folder.
        string startedIn = Environment.CurrentDirectory;
        try { Console.Title = "MnMSniffer"; } catch (Exception) { }
        try
        {
            var options = Cli.Parse(args);
            if (options.Help)
            {
                Console.WriteLine(HelpText);
                return 0;
            }
            if (options.List)
            {
                try
                {
                    GameCapture.ListDevices();
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    Console.Error.WriteLine("Install Npcap, then run this program again.");
                    HoldWindow();
                    return 1;
                }
            }
            string? keyError = CheckKey(options, out byte[]? suppliedKey);
            if (keyError != null)
            {
                Console.Error.WriteLine(keyError);
                HoldWindow();
                return 2;
            }
            int code = Capture(options, suppliedKey, string.IsNullOrWhiteSpace(options.OutDir) ? startedIn : options.OutDir!);
            HoldWindow();
            return code;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
        {
            Console.Error.WriteLine(ex.Message);
            HoldWindow();
            return 2;
        }
    }

    /// <summary>Keeps a double-clicked console on screen so the messages can be read.</summary>
    static void HoldWindow()
    {
        Console.WriteLine();
        Console.WriteLine("Press Enter to close this window.");
        try { Console.Out.Flush(); Console.ReadLine(); }
        catch (Exception) { }
    }

    static int Capture(CliOptions options, byte[]? key, string outDir)
    {
        using var game = WaitForGame();
        if (game == null) return 3;

        Directory.CreateDirectory(outDir);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string rawName = $"mnm_raw_{stamp}.pcap";
        string? parsedName = options.NoParse ? null : $"mnm_parsed_{stamp}.jsonl";
        string rawPath = Path.Combine(outDir, rawName);
        string? parsedPath = parsedName == null ? null : Path.Combine(outDir, parsedName);
        Log.Init(Path.Combine(outDir, "mnm_sniffer.log"));

        Log.Info($"Watching {game.Name} (pid {game.Pid}).");
        foreach (var other in game.Ignored)
            Log.Info($"Ignored other match {other}.");
        Log.Info($"Output folder: {Path.GetFullPath(outDir)}");
        Log.Info($"Raw dump: {rawName}");
        Log.Info("Files are written in the current directory and closed when this window closes or the game exits.");
        if (parsedName != null) Log.Info($"Parsed messages: {parsedName}");
        else Log.Info("Parsing is off. Raw dump only.");
        if (key != null) Log.Info("Using the session key from --key.");

        using var cts = new CancellationTokenSource();
        ConsoleStop.Install(() =>
        {
            RequestStop(cts, "Closing. Finishing the dump.");
            Finished.Wait(TimeSpan.FromSeconds(3));
        });
        WatchGame(game.Process, cts);

        var ports = new PortTable();
        using var refresher = new PortRefresher(game.Process, ports);
        using var capture = new GameCapture(options.Iface, ports);
        RawPcapWriter? raw = null;
        ParsedWriter? parsed = null;
        try
        {
            var adapter = WaitForAdapter(game.Process, capture, cts);
            if (adapter == null)
            {
                Log.Error("Stopped before the game client chose a network adapter. No dump was written.");
                return 3;
            }
            Log.Info($"Game client is using {GameCapture.Describe(adapter)}.");
            var link = capture.Open(adapter);
            raw = new RawPcapWriter(rawPath, link);
            capture.Use(raw);
            if (parsedPath != null) parsed = new ParsedWriter(parsedPath);
            capture.Start();
            int messages = 0;
            long failures = 0;
            if (parsed != null)
                (messages, failures) = ParseSession(capture, parsed, game.Pid, key, cts);
            else
            {
                foreach (var _ in capture.Read(cts.Token)) { }
            }
            Log.Info($"Closed {rawName} ({raw.Count} UDP packets).");
            if (parsedName != null)
                Log.Info($"Closed {parsedName} ({messages} decoded messages, {failures} decrypt failures).");
            if (capture.Dropped > 0)
                Log.Warn($"{capture.Dropped} packets are in the raw dump but were not queued for parsing.");
            if (parsed != null && messages == 0 && failures > 0)
                Log.Warn("Nothing decrypted. The raw dump was still saved.");
            return 0;
        }
        catch (Exception ex)
        {
            Log.Error(ex.Message);
            return 1;
        }
        finally
        {
            raw?.Dispose();
            parsed?.Dispose();
            Finished.Set();
        }
    }

    /// <summary>
    /// Returns at once when a matching process is already running. Otherwise prints a waiting
    /// line and polls until one appears, or until this window is closed.
    /// </summary>
    static GameProcess? WaitForGame()
    {
        var running = GameProcess.Find();
        if (running != null)
        {
            Console.WriteLine($"Game is already running: {running.Name} (pid {running.Pid}).");
            Console.Out.Flush();
            return running;
        }

        Console.WriteLine("MnMSniffer");
        Console.WriteLine("Waiting for the Monsters & Memories game client.");
        Console.WriteLine("Start the game. This window stays open until a process whose name contains \"MnM\" is running.");
        Console.Out.Flush();
        var stop = new ManualResetEventSlim(false);
        ConsoleStop.Install(() => stop.Set());
        int waited = 0;
        while (!stop.IsSet)
        {
            Thread.Sleep(1000);
            if (stop.IsSet) break;
            running = GameProcess.Find();
            if (running != null)
            {
                Console.WriteLine($"Game started: {running.Name} (pid {running.Pid}).");
                Console.Out.Flush();
                return running;
            }
            waited++;
            if (waited % 5 == 0)
            {
                Console.WriteLine($"{DateTime.Now:HH:mm:ss}  Still waiting for the Monsters & Memories game client...");
                Console.Out.Flush();
            }
        }
        Console.WriteLine("Closed before the game started. No dump was written.");
        return null;
    }

    static ICaptureDevice? WaitForAdapter(Process process, GameCapture capture, CancellationTokenSource cts)
    {
        bool announced = false;
        while (!cts.IsCancellationRequested)
        {
            try { if (process.HasExited) return null; }
            catch (Exception) { return null; }
            var chosen = AdapterChoice.Find(process.Id, capture.Candidates(), out var waiting);
            if (chosen != null) return chosen;
            if (!announced)
            {
                Console.WriteLine(waiting ?? "Waiting for the Monsters & Memories game client to open its network connection.");
                Console.Out.Flush();
                announced = true;
            }
            Thread.Sleep(500);
        }
        return null;
    }

    static void WatchGame(Process process, CancellationTokenSource cts)
    {
        _ = Task.Run(async () =>
        {
            try { await process.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) { return; }
            catch (Exception)
            {
                try
                {
                    while (!cts.IsCancellationRequested && !process.HasExited)
                        await Task.Delay(500, cts.Token);
                }
                catch (OperationCanceledException) { return; }
                catch (Exception) { return; }
                if (cts.IsCancellationRequested) return;
            }
            RequestStop(cts, "Game process exited. Finishing the dump.");
        });
    }

    static void RequestStop(CancellationTokenSource cts, string reason)
    {
        if (Interlocked.Exchange(ref _stop, 1) != 0) return;
        Log.Info(reason);
        try { Task.Delay(300).Wait(); } catch (Exception) { }
        try { cts.Cancel(); } catch (ObjectDisposedException) { }
    }

    static (int Messages, long Failures) ParseSession(GameCapture capture, ParsedWriter parsed, int pid, byte[]? suppliedKey, CancellationTokenSource cts)
    {
        var slot = new KeyBox(suppliedKey);
        var pending = new List<RawDatagram>();
        var samples = new List<byte[]>();
        SessionDecoder? decoder = suppliedKey == null ? null : new SessionDecoder(suppliedKey, parsed);
        int scanning = 0;
        int loggedProblem = 0;
        int loggedDrop = 0;
        int loggedSearch = 0;
        long nextTry = 0;
        if (decoder == null) Log.Info("Watching for the session key.");

        foreach (var datagram in capture.Read(cts.Token))
        {
            decoder = Activate(decoder, slot, parsed, pending);
            if (decoder != null)
            {
                decoder.Accept(datagram);
                continue;
            }
            pending.Add(datagram);
            if (pending.Count > 50000)
            {
                pending.RemoveAt(0);
                if (Interlocked.Exchange(ref loggedDrop, 1) == 0)
                    Log.Warn("Still no session key. The oldest packets will not be parsed. The raw dump has them.");
            }
            if (samples.Count < 4 && MnMEncryptionLayer.Framed(datagram.Payload))
                samples.Add(datagram.Payload);
            if (samples.Count < 2 || Volatile.Read(ref scanning) != 0 || Environment.TickCount64 < Volatile.Read(ref nextTry))
                continue;
            if (Interlocked.CompareExchange(ref scanning, 1, 0) != 0) continue;
            if (Interlocked.Exchange(ref loggedSearch, 1) == 0)
                Log.Info("Searching the game client for the session key. This can take a minute.");
            var snap = samples.ToArray();
            _ = Task.Run(() =>
            {
                try
                {
                    var found = SessionKey.Find(pid, snap, cts.Token, out var problem);
                    if (found != null) slot.Set(found);
                    else if (problem != null && Interlocked.Exchange(ref loggedProblem, 1) == 0)
                        Log.Warn(problem);
                }
                catch (Exception ex)
                {
                    if (Interlocked.Exchange(ref loggedProblem, 1) == 0)
                        Log.Warn($"Session key search failed: {ex.Message}");
                }
                finally
                {
                    Volatile.Write(ref nextTry, Environment.TickCount64 + 5000);
                    Interlocked.Exchange(ref scanning, 0);
                }
            });
        }

        decoder = Activate(decoder, slot, parsed, pending);
        if (decoder == null && Volatile.Read(ref scanning) == 1)
        {
            var until = Environment.TickCount64 + 2000;
            while (slot.Get() == null && Environment.TickCount64 < until && Volatile.Read(ref scanning) == 1)
                Thread.Sleep(50);
            decoder = Activate(decoder, slot, parsed, pending);
        }
        if (decoder == null)
            Log.Warn("No session key was found. The raw dump was saved and the parsed file is empty.");
        return (decoder?.Count ?? 0, decoder?.FailureCount ?? 0);
    }

    static SessionDecoder? Activate(SessionDecoder? decoder, KeyBox slot, ParsedWriter parsed, List<RawDatagram> pending)
    {
        if (decoder != null) return decoder;
        var key = slot.Get();
        if (key == null) return null;
        decoder = new SessionDecoder(key, parsed);
        Log.Info("Session key found. Parsing game messages.");
        foreach (var earlier in pending) decoder.Accept(earlier);
        pending.Clear();
        return decoder;
    }

    static string? CheckKey(CliOptions options, out byte[]? key)
    {
        key = null;
        if (string.IsNullOrWhiteSpace(options.KeyHex)) return null;
        if (options.NoParse) return "--key is not used with --no-parse.";
        var hex = options.KeyHex.Trim().Replace(" ", "").Replace("-", "");
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        try { key = Convert.FromHexString(hex); }
        catch (FormatException) { return "--key is not hexadecimal."; }
        if (key.Length != 32)
            return "--key must be 32 bytes (64 hex characters).";
        return null;
    }

    const string HelpText =
"""
MnMSniffer

Records the Monsters & Memories client's UDP in the directory you started it
from, and decodes the game messages. Close this window, or close the game,
and the files are finished.

You can start this program before the game. The window stays open and waits
until a process whose name contains "MnM" is running. If the game is already
running, capture starts immediately. The program reads that process only to
recover this login's session key, and it does not print the key.

  MnMSniffer.exe
  MnMSniffer.exe --no-parse

  --no-parse       Raw UDP dump only. Do not recover a key or write decoded messages
  --key <hex>      Use this 32-byte key instead of reading it from the game
  --out <dir>      Folder for the files. Default: the current directory
  --iface <text>   Only consider adapters whose name contains this text
  --list           Show capture devices and exit
  --help           Show this help

Output, in the current directory unless you pass --out:

  mnm_raw_<date>_<time>.pcap     Raw UDP frames. Open in Wireshark.
  mnm_parsed_<date>_<time>.jsonl Decoded messages. Omitted with --no-parse.
  mnm_sniffer.log                What the program did. The key is not written here.

Npcap has to be installed. If no capture device opens, or the key cannot be read,
run the program as the same user that is running the game.
Nothing is sent to the game or to the network.
""";
}

sealed class KeyBox
{
    byte[]? _key;
    public KeyBox(byte[]? key) => _key = key;
    public byte[]? Get() => Volatile.Read(ref _key);
    public void Set(byte[] key) => Volatile.Write(ref _key, key);
}

static class ConsoleStop
{
    delegate bool CtrlHandler(uint ctrlType);
    static CtrlHandler? _keepAlive;
    static Action? _onStop;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetConsoleCtrlHandler(CtrlHandler? handler, bool add);

    public static void Install(Action onStop)
    {
        _onStop = onStop;
        if (_keepAlive != null) return;
        _keepAlive = ctrl =>
        {
            // 0 Ctrl+C, 1 Ctrl+Break, 2 window close, 5 logoff, 6 shutdown.
            if (ctrl is 0 or 1 or 2 or 5 or 6)
            {
                try { _onStop?.Invoke(); } catch (Exception) { }
                return true;
            }
            return false;
        };
        SetConsoleCtrlHandler(_keepAlive, true);
    }
}

sealed class PortRefresher : IDisposable
{
    readonly Process _process;
    readonly PortTable _ports;
    readonly Timer _timer;
    int[] _last = Array.Empty<int>();
    int _warned;

    public PortRefresher(Process process, PortTable ports)
    {
        _process = process;
        _ports = ports;
        Refresh(null);
        _timer = new Timer(Refresh, null, 500, 500);
    }

    void Refresh(object? _)
    {
        try
        {
            if (_process.HasExited) return;
            var now = UdpPorts.ForProcess(_process.Id, out var warning);
            if (warning != null && Interlocked.Exchange(ref _warned, 1) == 0)
                Log.Warn(warning);
            if (now.SequenceEqual(_last)) return;
            _last = now;
            _ports.Replace(now);
            Log.Info(now.Length == 0
                ? "Waiting for the game to open a UDP socket."
                : "Game UDP ports: " + string.Join(", ", now));
        }
        catch (Exception ex)
        {
            if (Interlocked.Exchange(ref _warned, 1) == 0)
                Log.Warn($"Could not read UDP ports: {ex.Message}");
        }
    }

    public void Dispose() => _timer.Dispose();
}
