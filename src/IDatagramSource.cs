namespace MnMSniffer;

public interface IDatagramSource
{
    IEnumerable<RawDatagram> Read(CancellationToken ct);
}
