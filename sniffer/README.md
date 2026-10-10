# Forever Sniffer

Our own sniffer for the WoW Classic 1.60 beta client, written to replace Ymir (closed source, compiled with .NET NativeAOT, so it
cannot be decompiled into C#). It writes the same `.pkt` files, so WowPacketParser, Ymir Tool's viewer and `classic_re/sniff` read
them unchanged.

Build: `build_sniffer.cmd` -> `dist\ForeverSniffer.exe` (C# 5, the compiler that ships with Windows; no other installs). Needs Npcap
("WinPcap API-compatible mode"), like Ymir.

## Use

1. Start `ForeverSniffer.exe` **before logging in** (it needs the start of each connection).
2. Play. Close the game when done: the sniff is saved in `dumps\` and the sniffer exits a few seconds later.

Everything the window shows is also written to `ForeverSniffer.log` next to the exe (errors and crashes included).

Options: `--list` (adapters), `--iface <name>` (one adapter; Ymir's `interface.cfg` next to the exe is used too), `--out <folder>`,
`--strict` (like Ymir: when the recording goes wrong it closes the game and stops; without it the problem is only logged).
`--unpack <in.pkt> <out.pkt>` rewrites a sniff made before 2026-10-10 with the packets inside SMSG_COMPRESSED_PACKET /
SMSG_MULTIPLE_PACKETS (no game needed).
By default it listens on every adapter, including the Npcap loopback adapter, so it also records a server running on this PC.

## How it works (one file each)

| File | What it does |
|---|---|
| `Pcap.cs` | Npcap capture (`wpcap.dll` called directly), TCP only |
| `Tcp.cs` | Ethernet/loopback/IPv4/IPv6 -> TCP segments -> in-order byte streams (retransmissions, out-of-order) |
| `WorldConnection.cs` | World connection protocol: banner line, 16-byte packet headers, handshake challenges, switch to encryption (found by the AES-GCM tag; the counter counts every packet of a direction, plain ones too), compressed (seeded adler32) and multiple packets unpacked like Ymir, connection type from SMSG_CONNECT_TO (0 realm, 1 instance) |
| `Crypto.cs` | Key = first 32 bytes of HMAC-SHA512(session key, client challenge + server challenge + seed); AES-256-GCM, IV = counter + "CLNT"/"SRVR" (TrinityCore `WorldPacketCrypt`) |
| `Inflater.cs` | Raw deflate with the 32 KB window kept between packets (the server's deflate stream runs over the whole connection) |
| `ClientMemory.cs` | Session key from the game: known address per build (built-in table + Ymir Tool's learned `%APPDATA%\YmirTool\builds.txt`), else a memory search that only accepts a key that decrypts a captured packet |
| `PktWriter.cs` | PKT 3.1 like Ymir (sniffer id 0x17, 9 extra bytes per record = unix time in ms as a double + 0) |
| `Program.cs` | Adapters, worker thread, key handling, output in capture time order, stops when the game closes, `--unpack` |

## A new client build

Usually nothing to do: opcodes are not used, the PKT header takes the build from `WowB.exe`. If the session key address moved, the
sniffer finds it by itself (log line "session key found: pointer at image RVA 0x...") — add that RVA to `BuiltInSessionRva` in
`ClientMemory.cs` to make the next start instant. Only a change of the wire format or of the key derivation needs code changes.

Check a new version against Ymir by recording one session with both and running
`py -3 classic_re\sniff\compare_sniffs.py <ymir.pkt> <ours.pkt>`.

Verified 2026-10-10 against Ymir on the official beta (client 70338, one session of 6 connections): the same 23703 packets
(22107 server, 1596 client) with the same connection types. Only the order between two overlapping connections can differ: Ymir
stamps packets when it handles them, this sniffer when they were captured.
