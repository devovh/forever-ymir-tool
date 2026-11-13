// Finds the three WowB.exe addresses Ymir needs in a new client build.
//
// Each address is recognised by the layout of the 8-byte values around it (its "fingerprint"): zero, small number, heap pointer,
// pointer into one of the image's sections, or other. A new client build moves the address, but the neighbourhood keeps its
// layout, so sliding the fingerprint over the new image finds the same spot (classic_re/ymir_patch/fingerprint.py; checked
// 70124 <-> 70205 in both directions). Then a check that does not depend on the fingerprint confirms it:
//   locale table   the four pointers lead to the strings "enUS", "koKR", "frFR", "deDE"
//   locale index   a small number (the client's text language), right after the fingerprint spot
//   session object a heap pointer to an object with the 40-byte login session key at +0x48 (only after logging in)
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace YmirTool
{
    public enum CheckState { Ok, Unconfirmed, Failed }

    public sealed class FoundAddress
    {
        public string Key;              // locale_table, locale_index, session
        public long Rva;                // the value Ymir needs
        public int Score, MaxScore, RunnerUp;
        public CheckState Check;
        public string Detail;
    }

    public sealed class BuildAddresses
    {
        public int Build;
        public long LocaleIndex, LocaleTable, Session;
        public long Get(string key) { return key == "locale_index" ? LocaleIndex : key == "locale_table" ? LocaleTable : Session; }
        public void Set(string key, long v) { if (key == "locale_index") LocaleIndex = v; else if (key == "locale_table") LocaleTable = v; else Session = v; }
    }

    public static class Finder
    {
        public const int Window = 0x400;            // bytes on each side of the address
        const int Search = 0x200000;                // how far a new build may have moved it
        public static readonly string[] Keys = { "locale_table", "locale_index", "session" };

        // verified on the live client of each build (classic_re/ymir_patch/patch_ymir.py BUILDS); 70124 = the Ymir original
        public static readonly BuildAddresses[] KnownBuilds =
        {
            new BuildAddresses { Build = 70124, LocaleIndex = 0x5fa0bc4, LocaleTable = 0x496f3c0, Session = 0x5ffe108 },
            new BuildAddresses { Build = 70170, LocaleIndex = 0x5ef4484, LocaleTable = 0x48d43c0, Session = 0x5f519d8 },
            new BuildAddresses { Build = 70205, LocaleIndex = 0x5ef5804, LocaleTable = 0x48d53c0, Session = 0x5f52d08 },
            new BuildAddresses { Build = 70235, LocaleIndex = 0x5f06fc4, LocaleTable = 0x48e33c0, Session = 0x5f644d8 },
            new BuildAddresses { Build = 70245, LocaleIndex = 0x5f08004, LocaleTable = 0x48e43c0, Session = 0x5f65518 },
            new BuildAddresses { Build = 70291, LocaleIndex = 0x5f9fbd4, LocaleTable = 0x497a440, Session = 0x5ffd0f8 },
            // 70938 (Forever 1.60.1), all three from a dump of the running client:
            //   locale_table 0x3c02710 - 11 locale pointers in a row (enUS koKR frFR deDE ...), verified 227/227
            //   locale_index 0x483f908 - inside the locale record table at 0x483f900: [name pointer][index u32][flags u32]
            //                              entries of 0x18 bytes; the enUS record's index is 0, which is what Ymir reads
            //   session      0x4b69948 - ForeverSniffer: "pointer at image RVA 0x4b69948, key at +0x48"
            new BuildAddresses { Build = 70938, LocaleIndex = 0x483f908, LocaleTable = 0x3c02710, Session = 0x4b69948 },
        };

        // ------------------------------------------------------------------ builds learned by this tool (%APPDATA%\YmirTool)
        static string DataDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "YmirTool"); } }
        static string LearnedFile { get { return Path.Combine(DataDir, "builds.txt"); } }

        // build -> addresses (+ fingerprints); built-in builds plus the ones found and confirmed on this PC
        public static List<BuildAddresses> AllBuilds()
        {
            var list = new List<BuildAddresses>(KnownBuilds);
            foreach (var line in ReadLearned())
            {
                var p = line.Split(' ');
                if (p.Length >= 5 && p[0] == "build")
                {
                    int b = int.Parse(p[1]);
                    if (list.Any(x => x.Build == b)) continue;
                    list.Add(new BuildAddresses { Build = b, LocaleTable = Convert.ToInt64(p[2], 16), LocaleIndex = Convert.ToInt64(p[3], 16), Session = Convert.ToInt64(p[4], 16) });
                }
            }
            return list.OrderBy(x => x.Build).ToList();
        }

        static IEnumerable<string> ReadLearned()
        {
            try { return File.ReadAllLines(LearnedFile); } catch { return new string[0]; }
        }

        // A line that names the build but carries no addresses is a failed search that got saved anyway. Such a build used to
        // be treated as known, and every later search reused the 0x0 instead of looking again.
        public static bool IsUsable(BuildAddresses b)
        {
            return b != null && b.LocaleTable != 0 && b.LocaleIndex != 0 && b.Session != 0;
        }

        public static BuildAddresses Known(int build) { var b = AllBuilds().FirstOrDefault(x => x.Build == build); return IsUsable(b) ? b : null; }

        // If the neighbouring anchors moved by the same amount, this client keeps the same layout and the addresses can simply be
        // shifted. A search that drifted by tens of megabytes has not found anything - it is not a newer layout, and writing those
        // numbers into a copy of Ymir would only produce a binary that crashes.
        public static BuildAddresses Shifted(BuildAddresses from, long by)
        {
            if (from == null || by == 0) return null;
            var b = new BuildAddresses
            {
                Build = 0,
                LocaleTable = from.LocaleTable + by,
                LocaleIndex = from.LocaleIndex + by,
                Session = from.Session + by,
            };
            return IsUsable(b) ? b : null;
        }

        /// <summary>Every 8-byte aligned .data slot that holds a pointer into the image: (slot RVA, pointer value).</summary>
        /// <remarks>The sniffer walks the same set to find the session object; here it lets the key be confirmed by crypto.</remarks>
        public static List<KeyValuePair<long, long>> DataPointerSlots(GameImage img)
        {
            var slots = new List<KeyValuePair<long, long>>();
            var seen = new HashSet<long>();
            foreach (var s in img.Sections)
            {
                if (s.Name != ".data") continue;
                const int chunk = 1 << 20;
                for (long off = 0; off < s.Size; off += chunk)
                {
                    int n = (int)Math.Min(chunk, s.Size - off);
                    var b = img.Read(s.Rva + off, n);
                    if (b == null) continue;
                    for (int i = 0; i + 8 <= b.Length; i += 8)
                    {
                        long v = BitConverter.ToInt64(b, i);
                        if (v < img.Base || v >= img.Base + img.Size) continue;
                        if (!seen.Add(v)) continue;
                        slots.Add(new KeyValuePair<long, long>(s.Rva + off + i, v));
                    }
                }
            }
            return slots;
        }

        // fingerprints: the newest learned ones, else the built-in ones (70205)
        static Dictionary<string, string> Fingerprints(out int fromBuild)
        {
            var fp = new Dictionary<string, string>();
            fromBuild = 70205;
            foreach (var line in Resources.Text("fingerprints.txt").Split('\n'))
            {
                var p = line.Trim().Split(' ');
                if (p.Length == 2 && !line.StartsWith("#")) fp[p[0]] = p[1];
            }
            int best = 0;
            foreach (var line in ReadLearned())
            {
                var p = line.Split(' ');
                if (p.Length == 4 && p[0] == "fp" && int.Parse(p[1]) >= best && Keys.Contains(p[2]))
                {
                    best = int.Parse(p[1]); fp[p[2]] = p[3]; fromBuild = best;
                }
            }
            return fp;
        }

        public static void Learn(GameImage img, int build, Dictionary<string, FoundAddress> found)
        {

            // never save a failed search: a "build N 0 0 0" line makes N look known and its 0x0 stay forever
            foreach (var key in Keys)
            {
                var f = found[key];
                if (f.Check != CheckState.Ok || f.Rva == 0) return;
            }
            Directory.CreateDirectory(DataDir);
            var lines = ReadLearned().Where(l => !l.StartsWith("build " + build + " ") && !l.StartsWith("fp " + build + " ")).ToList();
            lines.Add(string.Format("build {0} {1:x} {2:x} {3:x}", build, found["locale_table"].Rva, found["locale_index"].Rva, found["session"].Rva));
            foreach (var key in Keys)
                lines.Add(string.Format("fp {0} {1} {2}", build, key, new string(Classify(img, Anchor(key, found[key].Rva) - Window, 2 * Window))));
            File.WriteAllLines(LearnedFile, lines);
        }

        // the fingerprint of the locale index sits 4 bytes before the value Ymir uses (it is the low half of a qword)
        static long Anchor(string key, long rva) { return key == "locale_index" ? rva - 4 : rva; }

        // ------------------------------------------------------------------ fingerprints
        public static char[] Classify(GameImage img, long rva, int length)
        {
            var raw = img.Read(rva, length);
            var c = new char[length / 8];
            for (int i = 0; i < c.Length; i++)
            {
                long v = BitConverter.ToInt64(raw, i * 8);
                if (v == 0) c[i] = '0';
                else if (v >= img.Base && v < img.Base + img.Size)
                {
                    var s = img.SectionOf(v - img.Base);
                    string n = s == null ? "" : s.Name;
                    c[i] = n == ".text" ? 'T' : n == ".rdata" ? 'R' : n == ".data" ? 'D' : n == ".pdata" ? 'P' : n == "_RDATA" ? 'U' : n == ".rsrc" ? 'S' : n == ".reloc" ? 'L' : 'Q';
                }
                else if ((ulong)v < 0x10000) c[i] = 's';
                else if (v >= 0x10000000000L && v < 0x7ff000000000L) c[i] = 'H';
                else c[i] = 'x';
            }
            return c;
        }

        // the best few fingerprint spots (each at least 8 qwords from a better one), best first
        static List<FoundAddress> Slide(GameImage img, string key, string fp, long near, int count)
        {
            long lo = Math.Max(0, near - Search - Window) & ~7L;
            var sig = Classify(img, lo, 2 * Search + 2 * Window);
            int n = fp.Length, max = fp.Count(ch => ch != '0');
            var scores = new int[Math.Max(0, sig.Length - n + 1)];
            for (int k = 0; k < scores.Length; k++)
            {
                int s = 0;
                for (int j = 0; j < n; j++) if (fp[j] != '0' && fp[j] == sig[k + j]) s++;
                scores[k] = s;
            }

            var picked = new List<int>();
            foreach (int k in Enumerable.Range(0, scores.Length).OrderByDescending(k => scores[k]))
            {
                if (picked.Any(p => Math.Abs(p - k) <= 8)) continue;
                picked.Add(k);
                if (picked.Count >= count + 1) break;
            }

            var result = new List<FoundAddress>();
            for (int i = 0; i < Math.Min(count, picked.Count); i++)
            {
                long rva = lo + picked[i] * 8L + Window;
                int runnerUp = picked.Where((p, j) => j != i).Select(p => scores[p]).DefaultIfEmpty(0).Max();
                result.Add(new FoundAddress { Key = key, Rva = key == "locale_index" ? rva + 4 : rva, Score = scores[picked[i]], MaxScore = max, RunnerUp = runnerUp });
            }
            if (result.Count == 0)
                result.Add(new FoundAddress { Key = key, Rva = near, MaxScore = max });
            return result;
        }

        // Finds all three; 'near' = the addresses of the closest known build (where to start looking).
        // The locale addresses are found first (their checks are exact); every address moves by about the same amount between builds,
        // so their shift predicts where the session object is. Of the close fingerprint matches for the session object, the one that
        // leads to a live session key wins (logged in), else the one nearest to the prediction (70245: fingerprint best 123 vs 121
        // picked a spot 0x1D000 away from the predicted one).
        // ------------------------------------------------------------------ search by structure, not by fingerprint
        // The 70205 fingerprints do not survive a locale table that grew from 4 entries to 11 (70938): every spot ties
        // and the search picks an arbitrary candidate. The client's own data still has a shape that cannot be faked:
        //   - a run of 8 locale name pointers in alphabetical order (enUS koKR frFR deDE ...) is the locale table;
        //   - the record table next to it, entries of 0x18 bytes [name pointer][index u32][flags u32], holds the
        //     index Ymir reads for the current locale (0 for enUS) - that is locale_index.
        // Both are found by walking the image once, which works on any build and needs no table.
        static readonly string[] LocaleNames = { "enUS", "koKR", "frFR", "deDE", "zhCN", "zhTW", "esES", "esMX", "ruRU" };

        public static bool IsLocaleName(GameImage img, long rva, string name)
        {
            // a qword read out of the image holds an absolute address, a section offset is an RVA: accept both
            if (rva > img.Base) rva -= img.Base;
            if (rva <= 0 || rva >= img.Size) return false;
            var got = img.Read(rva, name.Length + 1);
            if (got.Length < name.Length + 1 || got[name.Length] != 0) return false;
            for (int i = 0; i < name.Length; i++) if (got[i] != (byte)name[i]) return false;
            return true;
        }

        // Every run of 8 consecutive qwords that point at the locale names in order, first one wins.
        public static List<FoundAddress> FindLocaleTables(GameImage img)
        {
            var found = new List<FoundAddress>();
            var data = img.Sections.FirstOrDefault(s => s.Name == ".data");
            if (data == null) return found;
            long end = Math.Min(data.Rva + data.Size, img.Size) - 8 * (LocaleNames.Length - 1);
            for (long rva = data.Rva & ~7L; rva <= end; rva += 8)
            {
                bool ok = true;
                for (int i = 0; i < LocaleNames.Length && ok; i++)
                    ok = IsLocaleName(img, img.ReadInt64(rva + i * 8), LocaleNames[i]);
                if (ok) found.Add(new FoundAddress { Key = "locale_table", Rva = rva, Check = CheckState.Ok, Detail = "locale names in order" });
            }
            // the table can also live in .rdata (70938: 0x3c02710)
            var rdata = img.Sections.FirstOrDefault(s => s.Name == ".rdata");
            if (rdata != null)
            {
                long e2 = Math.Min(rdata.Rva + rdata.Size, img.Size) - 8 * (LocaleNames.Length - 1);
                for (long rva = rdata.Rva & ~7L; rva <= e2; rva += 8)
                {
                    bool ok = true;
                    for (int i = 0; i < LocaleNames.Length && ok; i++)
                        ok = IsLocaleName(img, img.ReadInt64(rva + i * 8), LocaleNames[i]);
                    if (ok) found.Add(new FoundAddress { Key = "locale_table", Rva = rva, Check = CheckState.Ok, Detail = "locale names in order" });
                }
            }
            return found;
        }

        // The locale record table: entries of 0x18 bytes, [qword name pointer][u32 index][u32 flags]. Ymir reads the
        // u32 right after the enUS record's name pointer. Walk .data for such a record and take that u32.
        public static FoundAddress FindLocaleIndexByRecords(GameImage img)
        {
            var data = img.Sections.FirstOrDefault(s => s.Name == ".data");
            if (data == null) return null;
            long end = Math.Min(data.Rva + data.Size, img.Size) - 0x18;
            for (long rva = data.Rva & ~7L; rva <= end; rva += 8)
            {
                if (!IsLocaleName(img, img.ReadInt64(rva), "enUS")) continue;
                // a record table, not a stray pointer: the next entry must be another locale name
                long next = rva + 0x18;
                long nextName = img.ReadInt64(next);
                bool looksLikeTable = false;
                foreach (var n in LocaleNames)
                    if (IsLocaleName(img, nextName, n)) { looksLikeTable = true; break; }
                if (!looksLikeTable) continue;
                int index = img.ReadInt32(rva + 8);
                if (index < 0 || index > 32) continue;
                return new FoundAddress { Key = "locale_index", Rva = rva + 8, Check = CheckState.Ok, Detail = "locale record table (" + index + ")" };
            }
            return null;
        }

        public static Dictionary<string, FoundAddress> FindAll(GameImage img, BuildAddresses near, out int fingerprintBuild)
        {
            var fps = Fingerprints(out fingerprintBuild);
            var result = new Dictionary<string, FoundAddress>();

            // structure first: the locale table and the record table give both addresses without a fingerprint
            var tables = FindLocaleTables(img);
            var byRecords = FindLocaleIndexByRecords(img);
            if (tables.Count > 0)
            {
                // with several runs, the one closest to the previous build's table is the live one
                var table = tables.OrderBy(f => Math.Abs(f.Rva - near.LocaleTable)).First();
                result["locale_table"] = table;
                if (byRecords != null) result["locale_index"] = byRecords;
            }
            foreach (var key in new[] { "locale_table", "locale_index" })
            {
                if (result.ContainsKey(key)) continue;
                var f = Slide(img, key, fps[key], Anchor(key, near.Get(key)), 1)[0];
                Verify(img, f);
                result[key] = f;
            }

            var shifts = new[] { "locale_table", "locale_index" }.Where(k => result[k].Check == CheckState.Ok).Select(k => result[k].Rva - near.Get(k)).ToList();
            long predicted = near.Session + (shifts.Count > 0 ? (long)shifts.Average() : 0);

            var candidates = Slide(img, "session", fps["session"], predicted, 6);
            int best = candidates[0].Score;
            FoundAddress chosen = null;
            foreach (var c in candidates.Where(c => c.Score >= best - 6))
                Verify(img, c);
            chosen = candidates.Where(c => c.Score >= best - 6 && c.Detail == "session key present")
                               .OrderBy(c => Math.Abs(c.Rva - predicted)).FirstOrDefault()
                  ?? ScanForSessionKey(img, predicted)
                  ?? ScanFromEveryBuild(img, result["locale_table"], predicted)
                  ?? candidates.Where(c => c.Score >= best - 6).OrderBy(c => Math.Abs(c.Rva - predicted)).First();

            // near the prediction with a live key: confirmed even if the fingerprint score alone is not decisive
            if (chosen.Detail == "session key present" && Math.Abs(chosen.Rva - predicted) <= 0x400)
                chosen.Check = CheckState.Ok;
            chosen.Detail += string.Format(" ({0:+#;-#;0} bytes from predicted 0x{1:x})", chosen.Rva - predicted, predicted);
            result["session"] = chosen;
            return result;
        }

        // a real login session key is 40 random bytes; heap objects full of pointers repeat bytes (00 00, d4 01 ...) and stay below this
        const int SessionKeyMinDistinct = 30;

        static byte[] ReadSessionKey(GameImage img, long pointer)
        {
            try { return img is LiveImage ? ((LiveImage)img).ReadAbsolute(pointer + 0x48, 40) : ((DumpImage)img).ReadAbsolute(pointer + 0x48, 40); }
            catch { return new byte[0]; }
        }

        // logged in, but no fingerprint match leads to a key: the qword near the predicted spot that does (70245: 0x20 from it)
        static FoundAddress ScanForSessionKey(GameImage img, long predicted)
        {
            if (!(img is LiveImage))
                return null;
            for (long d = 0; d <= 0x400; d += 8)
            {
                foreach (long rva in d == 0 ? new[] { predicted & ~7L } : new[] { (predicted & ~7L) + d, (predicted & ~7L) - d })
                {
                    long p = img.ReadInt64(rva);
                    if (p >= 0x10000000000L && p < 0x7ff000000000L && ReadSessionKey(img, p).Distinct().Count() >= SessionKeyMinDistinct)
                        return new FoundAddress { Key = "session", Rva = rva, Check = CheckState.Ok, Detail = "session key present" };
                }
            }
            return null;
        }

        // a build can sit closer to an older layout than to the nearest build number (70291 is 0x1000 below 70124, not near 70245):
        // predict the session from every known build's locale_table -> session distance and look around each
        static FoundAddress ScanFromEveryBuild(GameImage img, FoundAddress localeTable, long tried)
        {
            if (localeTable.Check != CheckState.Ok)
                return null;
            foreach (var b in AllBuilds().Select(b => b.Session + localeTable.Rva - b.LocaleTable).Distinct().OrderBy(p => Math.Abs(p - tried)))
            {
                if (Math.Abs(b - tried) <= 0x400)
                    continue;
                var f = ScanForSessionKey(img, b);
                if (f != null)
                    return f;
            }
            return null;
        }

        public static void Verify(GameImage img, FoundAddress f)
        {
            bool strong = f.Score >= f.MaxScore * 9 / 10 && f.Score - f.RunnerUp >= 3;
            if (f.Key == "locale_table")
            {
                string[] want = { "enUS", "koKR", "frFR", "deDE" };
                bool ok = true;
                for (int i = 0; i < 4 && ok; i++)
                {
                    long p = img.ReadInt64(f.Rva + i * 8);
                    var s = Encoding.ASCII.GetString(img.Read(p - img.Base, 5));
                    ok = s == want[i] + "\0";
                }
                f.Check = ok ? CheckState.Ok : CheckState.Failed;
                f.Detail = ok ? "enUS koKR frFR deDE" : "no locale names here";
            }
            else if (f.Key == "locale_index")
            {
                int v = img.ReadInt32(f.Rva);
                bool ok = v >= 0 && v < 32 && strong;
                f.Check = ok ? CheckState.Ok : CheckState.Failed;
                f.Detail = "value " + v;
            }
            else
            {
                long p = img.ReadInt64(f.Rva);
                if (!(p >= 0x10000000000L && p < 0x7ff000000000L))
                {
                    f.Check = CheckState.Failed; f.Detail = "not a pointer";
                    return;
                }
                int distinct = ReadSessionKey(img, p).Distinct().Count();
                if (distinct >= SessionKeyMinDistinct) { f.Check = strong ? CheckState.Ok : CheckState.Unconfirmed; f.Detail = "session key present"; }
                else { f.Check = strong ? CheckState.Unconfirmed : CheckState.Failed; f.Detail = "no session key (log in to confirm)"; }
            }
        }
    }
}
