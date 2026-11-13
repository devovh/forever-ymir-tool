// Ymir Tool: patches Ymir (the WoW Forever beta sniffer) for new client builds and shows sniff files.
//   YmirTool.exe                     the window
//   YmirTool.exe --selftest <report> checks finder, patcher and PKT reader against known files (no window)
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace YmirTool
{
    static class Program
    {
        public const string Version = "1.0.0";

        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length >= 3 && args[0] == "--session") return SessionCheck(args[1], args[2]);
            if (args.Length >= 2 && args[0] == "--selftest") return SelfTest(args[1], args.Skip(2).ToArray());
            L.Load();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }

        // --session <image dump> <sniff.pkt>: find the .data slot whose session key decrypts the sniff (no patterns involved).
        // Works on a dump taken from the running client, so the answer does not need the game to be logged in right now.
        static int SessionCheck(string dumpPath, string pktPath)
        {
            Console.WriteLine("sniff: " + pktPath);
            string detail;
            var samples = PktSamples.Load(pktPath, out detail);
            Console.WriteLine("  " + detail);
            if (samples.Count == 0) { Console.WriteLine("no handshake in that sniff"); return 2; }

            Console.WriteLine("image: " + dumpPath);
            var dumpBytes = File.ReadAllBytes(dumpPath);
            long imgBase, imgSize;
            var slots = KeyCheck.SlotsFromBytes(dumpBytes, out imgBase, out imgSize);
            Console.WriteLine(string.Format("  base 0x{0:x}, size 0x{1:x}", imgBase, imgSize));
            Console.WriteLine("  .data pointer slots: " + slots.Count);

            int tried = 0;
            foreach (var slot in slots)
            {
                int at;
                var key = KeyCheck.ReadKeyFromBytes(dumpBytes, slot.Value, 0x40, out at);
                if (Environment.GetEnvironmentVariable("YMT_DEBUG") != null && tried < 3)
                    Console.WriteLine(string.Format("  dbg slot 0x{0:x} ptr 0x{1:x} -> key {2}", slot.Key, slot.Value, key == null ? "null" : "ok"));
                if (key == null) continue;
                tried++;
                if (!KeyCheck.Works(key, samples)) continue;
                Console.WriteLine(string.Format("CONFIRMED: session pointer at image RVA 0x{0:x}, key at +0x{1:x}", slot.Key, at));
                Console.WriteLine("          key " + BitConverter.ToString(key).Replace("-", "").ToLowerInvariant());
                return 0;
            }
            Console.WriteLine(string.Format("dbg slots={0} tried={1} base=0x{2:x} size=0x{3:x} firstSlot=0x{4:x}->0x{5:x}", slots.Count, tried, imgBase, imgSize, slots.Count > 0 ? slots[0].Key : 0, slots.Count > 0 ? slots[0].Value : 0));
            Console.WriteLine(string.Format("no working key: {0} candidate(s) tried against {1} packet(s)", tried, samples.Count));
            return 3;
        }

        // args: [70124 dump] [70205 dump] [ymir regedit.exe] [regedit_70235.exe made by patch_ymir.py] [sniff.pkt]
        static int SelfTest(string report, string[] files)
        {
            var sb = new StringBuilder();
            bool allOk = true;
            Action<bool, string> check = (ok, text) => { sb.AppendLine((ok ? "PASS  " : "FAIL  ") + text); if (!ok) allOk = false; };
            try
            {
                check(Opcodes.Count > 3000, "opcode names loaded: " + Opcodes.Count + " (CMSG_HOTFIX_REQUEST = " + Opcodes.Name(0x440011, false) + ")");
                var b205 = Finder.Known(70205);
                foreach (var pair in new[] { Tuple.Create(files[0], 70124), Tuple.Create(files[1], 70205) })
                {
                    var img = new DumpImage(pair.Item1);
                    int fpBuild;
                    var found = Finder.FindAll(img, b205, out fpBuild);
                    var want = Finder.Known(pair.Item2);
                    foreach (var f in found.Values)
                        check(f.Rva == want.Get(f.Key) && f.Check != CheckState.Failed,
                              string.Format("dump {0}: {1} 0x{2:x} (want 0x{3:x}) score {4}/{5} next {6} check {7}: {8}",
                                            pair.Item2, f.Key, f.Rva, want.Get(f.Key), f.Score, f.MaxScore, f.RunnerUp, f.Check, f.Detail));
                }
                var source = File.ReadAllBytes(files[2]);
                check(YmirPatcher.IsOriginal(source) && YmirPatcher.CheckSource(source) == null, "Ymir original recognised");
                var patched = YmirPatcher.Patch(source, 70235, Finder.Known(70235));
                var python = File.ReadAllBytes(files[3]);
                check(patched.SequenceEqual(python), "Ymir for 70235 identical to patch_ymir.py output (" + patched.Length + " bytes)");
                var pkt = PktFile.Open(files[4]);
                var named = pkt.Packets.Count(p => Opcodes.Name(p.Opcode, p.FromServer).Length > 0);
                check(pkt.Packets.Count > 0, string.Format("sniff: build {0}, {1} packets ({2} named), {3:0.0} min",
                      pkt.Build, pkt.Packets.Count, named, pkt.Packets.Last().TimeMs / 60000.0));

                // live follow: the same file written in uneven pieces (cut inside packets) must end with the same packets
                var all = File.ReadAllBytes(files[4]);
                string temp = Path.Combine(Path.GetTempPath(), "ymirtool_growing.pkt");
                int[] cuts = { 120, all.Length / 3 + 7, all.Length * 2 / 3 + 13, all.Length };
                File.WriteAllBytes(temp, all.Take(cuts[0]).ToArray());
                var growing = PktFile.Open(temp);
                int prevCut = cuts[0];
                foreach (int cut in cuts.Skip(1))
                {
                    using (var fs = new FileStream(temp, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                        fs.Write(all, prevCut, cut - prevCut);
                    prevCut = cut;
                    growing.Refresh();
                }
                bool same = growing.Packets.Count == pkt.Packets.Count
                            && growing.Packets.Zip(pkt.Packets, (a, b) => a.Opcode == b.Opcode && a.Length == b.Length && a.TimeMs == b.TimeMs).All(x => x);
                check(same, "live follow: file written in 4 pieces gives the same " + growing.Packets.Count + " packets");
                File.WriteAllBytes(temp, all.Take(all.Length / 2).ToArray());          // replaced by a shorter file
                growing.Refresh();
                check(growing.Packets.Count > 0 && growing.Packets.Count < pkt.Packets.Count, "replaced file read again from the start: " + growing.Packets.Count + " packets");
                File.Delete(temp);

                // content search: the rare's name is in the creature query reply
                var text = System.Text.Encoding.UTF8.GetBytes("coldrasp");
                int hit = -1, at = -1;
                for (int i = 0; i < pkt.Packets.Count && hit < 0; i++) { at = pkt.Find(pkt.Packets[i], text, true); if (at >= 0) hit = i; }
                check(hit >= 0, string.Format("search text \"coldrasp\" (any case): packet #{0} {1} at byte {2}", hit,
                      hit >= 0 ? Opcodes.Name(pkt.Packets[hit].Opcode, pkt.Packets[hit].FromServer) : "", at));
                var hexPattern = System.Text.Encoding.ASCII.GetBytes("Coldrasp");
                check(hit >= 0 && pkt.Find(pkt.Packets[hit], hexPattern, false) == at, "search hex " + BitConverter.ToString(hexPattern).Replace("-", " ") + ": same place");
            }
            catch (Exception ex) { check(false, ex.ToString()); }
            File.WriteAllText(report, sb.ToString());
            return allOk ? 0 : 1;
        }
    }
}
