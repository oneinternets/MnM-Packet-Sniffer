namespace MnMSniffer;

sealed class CliOptions
{
    public bool Help { get; init; }
    public bool List { get; init; }
    public bool NoParse { get; init; }
    public string? KeyHex { get; init; }
    public string? Iface { get; init; }
    public string? OutDir { get; init; }
}

static class Cli
{
    public static CliOptions Parse(string[] args)
    {
        bool help = false, list = false, noParse = false, parse = false;
        string? key = null, iface = null, outDir = null;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--help":
                case "-h":
                case "/?":
                    help = true;
                    break;
                case "--list":
                    list = true;
                    break;
                case "--parse":
                    parse = true;
                    break;
                case "--no-parse":
                    noParse = true;
                    break;
                case "--key":
                    key = Need(args, ref i, "--key");
                    break;
                case "--iface":
                    iface = Need(args, ref i, "--iface");
                    break;
                case "--out":
                    outDir = Need(args, ref i, "--out");
                    break;
                default:
                    throw new ArgumentException($"Unknown argument '{args[i]}'. Run MnMSniffer.exe --help.");
            }
        }
        if (parse && noParse)
            throw new ArgumentException("Pass either --parse or --no-parse.");
        return new CliOptions
        {
            Help = help,
            List = list,
            NoParse = noParse,
            KeyHex = key,
            Iface = iface,
            OutDir = outDir
        };
    }

    static string Need(string[] args, ref int i, string flag)
    {
        if (i + 1 >= args.Length || args[i + 1].StartsWith("--"))
            throw new ArgumentException($"{flag} needs a value.");
        return args[++i];
    }
}
