namespace MnMSniffer;

/// <summary>UDP ports of the game, replaced as a whole from the refresh thread.</summary>
sealed class PortTable
{
    int[] _ports = Array.Empty<int>();

    public void Replace(int[] ports) => Volatile.Write(ref _ports, ports);

    public bool Contains(int port)
    {
        var ports = Volatile.Read(ref _ports);
        for (int i = 0; i < ports.Length; i++)
            if (ports[i] == port) return true;
        return false;
    }
}
