# MnM-Packet-Sniffer (MnMSniffer)
Packet sniffer for Monsters &amp; Memories


MnMSniffer
==========

This is the source for MnMSniffer, a Windows console program.

MnMSniffer watches one running process whose name contains "MnM". It records
that process's UDP and, unless parsing is turned off, reads the process to
recover the AES-256 session key for the current login. It writes a raw packet
capture and a decoded message log in the folder the program was started from.

The dump is closed when the command window closes or when that process exits.
Nothing is injected into the process, and nothing is sent on the network.


What is in this directory
-------------------------

MnMSniffer.csproj    Project file. The target is .NET 10 on Windows.
src\                 C# source.

Building restores SharpPcap 6.3.1 from NuGet. Npcap is not included.


What you need
-------------

- Windows
- The .NET 10 SDK, to build
- Npcap, installed before the first capture: https://npcap.com/
  The program reads packets through Npcap.
- A running process whose name contains "MnM". Capitalization does not matter.
  The program never watches itself.

If the program cannot open a capture device, close it and start it from an
Administrator command prompt. If it cannot read the session key, run it as the
same user that owns the watched process.


Build
-----

From this directory:

    dotnet build MnMSniffer.csproj -c Release

The executable is:

    bin\Release\net10.0-windows\MnMSniffer.exe

A self-contained build does not need a separate .NET install on the machine
that runs it:

    dotnet publish MnMSniffer.csproj -c Release -r win-x64 --self-contained true -o publish

That writes publish\MnMSniffer.exe.


Start a capture
---------------

1. Open a command prompt in the folder where the dump should go, or
   double-click MnMSniffer.exe. The dump is written in the folder the program
   was started from. Double-clicking writes the files next to the exe, because
   Windows sets that folder as the current directory.
2. Run:

    MnMSniffer.exe

The command window stays open. If no matching process is running yet, it
prints a waiting line and checks about once a second. When a process whose
name contains "MnM" is already running, capture starts at once.

The login can happen before the program starts, or while it is waiting. It
needs a few encrypted packets and a read of the process before it can recover
the key. The window prints the process it is watching (name and process id),
the output folder, and the file names. It then prints:

    Session key found. Parsing game messages.

The key itself is not printed and is not written to the log.

Leave the window open during the session. A line named "Game UDP ports"
appears once the client opens its UDP sockets. Until then the log says it is
waiting for a UDP socket. That is normal before the client has connected.

When more than one process name contains "MnM", the program watches the one
that owns the most UDP sockets and ignores the others.


Finish the capture
------------------

The dump file is created when capture starts and grows while the client is
running. It is finished, flushed, and closed when any of these happen:

- The command window is closed
- Ctrl+C is pressed
- The watched process exits

Copy or open the dump after one of those. A file copied while the window is
still open can be missing the last packets.


Files written
-------------

mnm_raw_yyyyMMdd_HHmmss.pcap
    Every run. A packet capture of the UDP datagrams on the client's sockets,
    in both directions. Open it in Wireshark. The payloads are the bytes that
    were on the wire. The messages are encrypted, so Wireshark does not show
    message names.

mnm_parsed_yyyyMMdd_HHmmss.jsonl
    Every run, unless --no-parse was passed. One decoded message per line.

mnm_sniffer.log
    Every run, appended. The process id, port changes, and the final packet
    count. The key is not written here.

The time in the file name is local time.

The pcap contains the IP addresses and ports that were on those UDP datagrams.
It stays on this computer.

The program reads the client's UDP sockets and opens one local adapter. A
socket bound to a specific address selects the adapter that owns that address.
A socket bound to every address follows this PC's default route. Other
adapters are left closed. Tunnel and virtual adapters are skipped. --iface
limits the choice to adapters whose name or description contains the text.


Decoded messages
----------------

Decoding is on by default. After a few encrypted datagrams arrive, the program
reads the client process, finds the AES key for this login, and writes one
decoded message per line. The read is query and memory-read only. Packets seen
before the key is found are decoded once the key is found. Those packets are
already in the pcap.

To keep the raw dump and skip the key read and the JSONL file:

    MnMSniffer.exe --no-parse

A decoded line looks like this. The values are an example, not a captured session:

    {"ts":1710000000000,"dir":"s2c","channel":0,"opcode":34,"name":"UpdateHealth","fields":{"id":1,"health":40,"maxHealth":100},"full":true,"len":14,"data":"IgAA..."}

ts        UTC time in milliseconds
dir       s2c is server to client. c2s is client to server.
channel   LiteNetLib channel
opcode    Numeric message id
name      Message name, when this build knows it
fields    Decoded fields. null when this build has no field layout for that message
full      true when the decoder consumed the whole message
len       Length of the decrypted message
data      Decrypted message bytes, base64

Datagrams that are not encrypted messages stay in the pcap and are left out of
the JSONL file. If no key matches, the pcap is still saved, the JSONL file is
empty, and the log says no session key was found.

Parsed lines can contain whatever that session carried: names, chat text, and
positions. The JSONL file is written only to the output folder.


Options
-------

    MnMSniffer.exe
    MnMSniffer.exe --no-parse
    MnMSniffer.exe --list
    MnMSniffer.exe --help

--no-parse       Raw pcap only. Do not recover a key. Do not write
                 mnm_parsed_*.jsonl.
--key <hex>      Use this 32-byte key (64 hex characters) instead of reading
                 it from the process.
--out <dir>      Write the files here instead of the current directory.
                 The directory is created if needed.
--iface <text>   Only consider local adapters whose name or description
                 contains this text. By default the program picks the one
                 adapter the client is using.
--list           Print capture devices and exit.
--help           Print the short help and exit.

Exit codes:

0    Finished, or help, or a successful device list.
1    Capture failed, or no capture device could be opened.
2    The arguments or the key were rejected.
3    The window was closed before a matching process started, or before
     the client had chosen an adapter.

After a capture, or after an error, the window stays open until Enter is pressed.


Limits
------

- Packets are observed only. The program does not send, modify, or inject them.
- There is no built-in session key. With parsing on, the running process is
  read only to find that login's key. The key is not printed or saved.
- TCP is not recorded. UDP sockets owned by other programs are not recorded.
- The dump is not uploaded.

A client update can add messages this build does not name. Those messages are
still stored. In the JSONL file their name is null and fields is null, with
the decrypted bytes in data. The raw pcap is unchanged.

This is confirmed to work with the Early Access version of MnM as of Nov 5, 2026 
version publish-0.30.5.2
