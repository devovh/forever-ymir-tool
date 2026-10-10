// Forever Sniffer: records the world connections of the Classic 1.60 beta client into Ymir-compatible .pkt files.
//
// Start it before logging in (it needs the start of each connection), play, close the game: the sniff is saved in dumps\ and the
// sniffer exits a few seconds later, like Ymir.
//   ForeverSniffer.exe                      capture on every network adapter (incl. the Npcap loopback adapter for a local server)
//   ForeverSniffer.exe --list               show the adapters
//   ForeverSniffer.exe --iface <name>       capture on one adapter only (name from --list; Ymir's interface.cfg works too)
//   ForeverSniffer.exe --out <folder>       where the sniffs go (default: dumps next to the exe)
//   ForeverSniffer.exe --strict             like Ymir: if the recording goes wrong (stream lost, a packet does not decrypt, no session
//                                           key), save the sniff, close the game and exit, so nobody plays on unrecorded.
//                                           Without it the problem is logged and the game keeps running.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace ForeverSniffer
{
    public static class Program
    {
        static readonly ConcurrentQueue<CapturedFrame> frames = new ConcurrentQueue<CapturedFrame>();
        static readonly AutoResetEvent frameReady = new AutoResetEvent(false);
        static volatile bool stopping, strict, keyNotFound;

        static readonly Dictionary<string, WorldConnection> byFlow = new Dictionary<string, WorldConnection>();   // "src>dst"
        static readonly List<WorldConnection> connections = new List<WorldConnection>();
        static readonly HashSet<string> ignored = new HashSet<string>();
        static PktWriter writer;
        static string outDir;
        static GameClient game;
        static long lastPacketMicros;

        // session key search on a background thread (only for a client build whose key address is not known)
        static Thread search;
        static volatile byte[] searchResult;
        static DateTime keyWaitStart = DateTime.MinValue, lastKeyTry = DateTime.MinValue;
        static bool knownKeyFailLogged;

        public static int Main(string[] args)
        {
            Console.Title = "Forever Sniffer";
            // everything shown in the window also goes to ForeverSniffer.log next to the exe (crashes too)
            try
            {
                logFile = new StreamWriter(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ForeverSniffer.log"), true) { AutoFlush = true };
                logFile.WriteLine();
                logFile.WriteLine("==== {0:yyyy-MM-dd HH:mm:ss} ForeverSniffer {1}", DateTime.Now, string.Join(" ", args));
            }
            catch (IOException) { }
            AppDomain.CurrentDomain.UnhandledException += (s, e) => Log("CRASH: " + e.ExceptionObject);
            string err = Pcap.Load();
            if (err != null) { Log(err); Pause(); return 1; }

            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            outDir = Path.Combine(exeDir, "dumps");
            string iface = null;
            for (int i = 0; i < args.Length; ++i)
            {
                if (args[i] == "--list")
                {
                    foreach (var d in Pcap.Devices()) Console.WriteLine(d);
                    return 0;
                }
                if (args[i] == "--unpack" && i + 2 < args.Length) return UnpackFile(args[i + 1], args[i + 2]);
                if (args[i] == "--iface" && i + 1 < args.Length) iface = args[++i];
                else if (args[i] == "--out" && i + 1 < args.Length) outDir = args[++i];
                else if (args[i] == "--strict") strict = true;
            }
            string cfg = Path.Combine(exeDir, "interface.cfg");
            if (iface == null && File.Exists(cfg)) iface = File.ReadAllText(cfg).Trim();
            Directory.CreateDirectory(outDir);

            var devices = Pcap.Devices().Where(d => iface == null || d.Name == iface).ToList();
            if (devices.Count == 0) { Log("no capture adapter" + (iface != null ? " named " + iface : "") + "; see --list"); Pause(); return 1; }
            foreach (var d in devices)
            {
                var dev = d;
                new Thread(() => Pcap.Run(dev.Name, f => { frames.Enqueue(f); frameReady.Set(); }, () => stopping, Log)) { IsBackground = true, Name = "capture" }.Start();
            }
            Log(string.Format("capturing on {0} adapter(s). Start the game and log in; close the game to finish the sniff.", devices.Count));
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; stopping = true; frameReady.Set(); };

            DateTime lastStatus = DateTime.UtcNow;
            while (!stopping)
            {
                frameReady.WaitOne(200);
                CapturedFrame f;
                try
                {
                    while (frames.TryDequeue(out f)) OnFrame(f);
                    HandleKeys();
                    FlushQueue(false);
                }
                catch (Exception e) { Log("ERROR: " + e); }
                string problem = keyNotFound ? "no session key"
                    : connections.Any(c => c.Broken) ? "a connection's stream was lost"
                    : connections.Any(c => c.DecryptFailures > 0) ? "a packet did not decrypt" : null;
                if (strict && problem != null)
                {
                    Log("--strict: " + problem + ": closing the game and stopping");
                    try { if (game != null && !game.HasExited) game.Process.Kill(); } catch (Exception e) { Log("could not close the game: " + e.Message); }
                    break;
                }
                if ((DateTime.UtcNow - lastStatus).TotalSeconds >= 30 && writer != null)
                {
                    lastStatus = DateTime.UtcNow;
                    Log(string.Format("{0} packets in {1} connection(s)", writer.Records + queue.Count, connections.Count));
                }
                // done like Ymir: the game was recorded and has closed
                if (game != null && game.HasExited && connections.All(c => c.Closed || NowMicros() - lastPacketMicros > 5000000)) break;
            }
            Finish();
            return 0;
        }

        static void OnFrame(CapturedFrame f)
        {
            var s = Frames.Parse(f);
            if (s == null) return;
            string flow = s.Source + ">" + s.Destination;
            WorldConnection c;
            if (byFlow.TryGetValue(flow, out c))
            {
                c.Add(s, s.Source == c.ServerEnd);
                return;
            }
            if (s.Payload.Length == 0 || ignored.Contains(flow)) return;
            if (!WorldConnection.StartsWithBanner(s.Payload)) { if (ignored.Count < 100000) ignored.Add(flow); return; }

            bool fromServer = WorldConnection.IsServerBanner(s.Payload);
            string clientEnd = fromServer ? s.Destination : s.Source, serverEnd = fromServer ? s.Source : s.Destination;
            c = new WorldConnection(connections.Count, clientEnd, serverEnd, OnPacket, Log);
            connections.Add(c);
            byFlow[clientEnd + ">" + serverEnd] = c;
            byFlow[serverEnd + ">" + clientEnd] = c;
            ignored.Remove(clientEnd + ">" + serverEnd);
            ignored.Remove(serverEnd + ">" + clientEnd);
            Log(string.Format("world connection {0}: {1} <-> {2}", c.Index, clientEnd, serverEnd));
            c.Add(s, fromServer);
        }

        static void OnPacket(WorldConnection c, WirePacket p)
        {
            if (writer == null)
            {
                if (game == null) game = GameClient.Find();
                int build = game != null ? game.Build : 0;
                string version = game != null ? game.Version : "unknown";
                string path = Path.Combine(outDir, string.Format("dump_{0}_{1:yyyy-MM-dd_HH-mm-ss}.pkt", version, DateTime.Now));
                writer = new PktWriter(path, build, game != null ? game.Locale() : "enUS", p.UnixMicros);
                Log("recording to " + path + (game == null ? " (game client not found: build unknown)" : " (client " + version + ")"));
            }
            // written in capture time order: packets of a connection still waiting for its key come later, so the others wait too
            queue.Add(new Queued { Seq = queueSeq++, Type = c.Type, Packet = p });
            lastPacketMicros = Math.Max(lastPacketMicros, p.UnixMicros);
        }

        sealed class Queued { public long Seq; public int Type; public WirePacket Packet; }
        static readonly List<Queued> queue = new List<Queued>();
        static long queueSeq;

        // writes the queued packets older than everything still held back (all of them when flushAll)
        static void FlushQueue(bool flushAll)
        {
            if (queue.Count == 0) return;
            // a connection whose key search ended without a key holds nothing back any more
            long horizon = flushAll ? long.MaxValue : connections.Where(c => !(c.Searched && !c.HasKey && search == null))
                .Select(c => c.HeldSinceMicros).DefaultIfEmpty(long.MaxValue).Min();
            var ready = queue.Where(q => q.Packet.UnixMicros < horizon).OrderBy(q => q.Packet.UnixMicros).ThenBy(q => q.Seq).ToList();
            if (ready.Count == 0) return;
            foreach (var q in ready)
                writer.Write(q.Packet.FromServer, q.Type, q.Packet.UnixMicros, q.Packet.Data);     // like Ymir: the connection type, 0 realm, 1 instance
            var written = new HashSet<Queued>(ready);
            queue.RemoveAll(written.Contains);
        }

        static void HandleKeys()
        {
            var waiting = connections.Where(c => c.NeedsKey && !c.Broken).ToList();
            if (waiting.Count == 0) { keyWaitStart = DateTime.MinValue; return; }
            if (keyWaitStart == DateTime.MinValue) keyWaitStart = DateTime.UtcNow;

            var result = searchResult;
            if (result != null)
            {
                searchResult = null;
                foreach (var c in waiting) if (c.TryKey(result)) Log(string.Format("connection {0}: decrypting (key from the search)", c.Index));
                return;
            }
            if ((DateTime.UtcNow - lastKeyTry).TotalMilliseconds < 300) return;
            lastKeyTry = DateTime.UtcNow;

            if (game == null || game.HasExited) game = GameClient.Find();
            if (game == null) return;
            var key = game.SessionKeyAtKnownAddress();
            if (key != null)
            {
                foreach (var c in waiting)
                    if (c.TryKey(key)) Log(string.Format("connection {0}: decrypting", c.Index));
                if (waiting.Any(c => c.NeedsKey) && !knownKeyFailLogged)
                {
                    knownKeyFailLogged = true;
                    Log(string.Format("the 40 bytes at the known address (build {0}, RVA 0x{1:x}) do not decrypt the connection yet (key {2}...)",
                        game.Build, game.KnownSessionRva(), BitConverter.ToString(key, 0, 4)));
                }
            }
            else if (!knownKeyFailLogged)
            {
                knownKeyFailLogged = true;
                Log(game.KnownSessionRva() == 0 ? string.Format("no known session key address for client build {0}", game.Build)
                                                : "the known session key address holds no session object yet");
            }

            // unknown build (or the address moved): search the client once the known address had its chance
            var still = waiting.FirstOrDefault(c => c.NeedsKey && !c.Searched);
            if (still != null && search == null && (DateTime.UtcNow - keyWaitStart).TotalSeconds > 15)   // the known address gets a new connection's key a few seconds late
            {
                Log(game.KnownSessionRva() == 0
                    ? string.Format("client build {0} is new: searching the session key in the game's memory", game.Build)
                    : "the session key is not at the known address: searching the game's memory");
                still.Searched = true;
                var samples = still.Samples();
                byte[] cc = still.ClientChallenge, sc = still.ServerChallenge;
                var g = game;
                search = new Thread(() =>
                {
                    byte[] found = null;
                    try { found = g.SearchSessionKey(k => WorldConnection.KeyWorks(k, cc, sc, samples), Log); }
                    catch (Exception e) { Log("ERROR in the session key search: " + e); }
                    if (found == null) { Log("session key not found: this connection cannot be decrypted"); keyNotFound = true; }
                    searchResult = found;
                    search = null;
                }) { IsBackground = true, Name = "key search" };
                search.Start();
            }
        }

        // Rewrites a sniff with the packets inside SMSG_COMPRESSED_PACKET / SMSG_MULTIPLE_PACKETS (sniffs of Forever Sniffer before 2026-10-10)
        static int UnpackFile(string input, string outputPath)
        {
            var d = File.ReadAllBytes(input);
            int build = BitConverter.ToInt32(d, 6);
            string locale = System.Text.Encoding.ASCII.GetString(d, 10, 4);
            uint startTime = BitConverter.ToUInt32(d, 54);
            int pos = 66 + BitConverter.ToInt32(d, 62);
            var conns = new Dictionary<int, WorldConnection>();
            var firstClient = new HashSet<int>();
            PktWriter w = null;
            int written = 0;
            while (pos + 20 <= d.Length)
            {
                bool fromServer = d[pos] == (byte)'S';
                int conn = BitConverter.ToInt32(d, pos + 4), extra = BitConverter.ToInt32(d, pos + 12), length = BitConverter.ToInt32(d, pos + 16);
                long micros = extra >= 8 ? (long)(BitConverter.ToDouble(d, pos + 20) * 1000) : (startTime + BitConverter.ToUInt32(d, pos + 8) / 1000) * 1000000L;
                var data = new byte[length];
                Buffer.BlockCopy(d, pos + 20 + extra, data, 0, length);
                pos += 20 + extra + length;
                if (w == null) w = new PktWriter(outputPath, build, locale, micros);
                WorldConnection c;
                if (!conns.TryGetValue(conn, out c))
                {
                    var writer = w;
                    c = new WorldConnection(conn, "", "", (cc, p) => { writer.Write(p.FromServer, cc.Type, p.UnixMicros, p.Data); ++written; }, Log);
                    conns[conn] = c;
                }
                // the second packet of a connection tells its type: a short client handshake = instance connection
                if (!fromServer && firstClient.Add(conn) && length >= 4 + 72 && length < 4 + 200)
                {
                    int type;
                    c.Continued = true;
                    c.Type = WorldConnection.ConnectToTypes.TryGetValue(BitConverter.ToUInt64(data, 4 + 64), out type) ? type : 1;
                }
                c.Replay(new WirePacket { FromServer = fromServer, Data = data, UnixMicros = micros });
            }
            if (w != null) w.Dispose();
            Log(string.Format("{0}: {1} packets written to {2}", input, written, outputPath));
            return 0;
        }

        static void Finish()
        {
            stopping = true;
            foreach (var c in connections) c.FlushUndecrypted();
            if (writer != null) FlushQueue(true);
            if (writer != null)
            {
                writer.Dispose();
                Log(string.Format("sniff saved: {0} packets", writer.Records));
            }
            else Log("nothing recorded (no world connection seen)");
        }

        static long NowMicros() { return (DateTime.UtcNow.Ticks - 621355968000000000L) / 10; }

        static readonly object logLock = new object();
        static StreamWriter logFile;
        public static void Log(string text)
        {
            lock (logLock)
            {
                string line = string.Format("[{0:HH:mm:ss}] {1}", DateTime.Now, text);
                Console.WriteLine(line);
                if (logFile != null) try { logFile.WriteLine(line); } catch (IOException) { }
            }
        }

        static void Pause()
        {
            if (!Console.IsInputRedirected) { Console.WriteLine("press a key"); Console.ReadKey(true); }
        }
    }
}
