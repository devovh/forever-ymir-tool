// Npcap capture (wpcap.dll in WinPcap API-compatible mode, the same driver Ymir uses), called directly: no SharpPcap needed.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ForeverSniffer
{
    public sealed class CapturedFrame
    {
        public int LinkType;
        public long UnixMicros;     // capture time
        public byte[] Data;
    }

    public sealed class PcapDevice
    {
        public string Name, Description;
        public override string ToString() { return Name + (string.IsNullOrEmpty(Description) ? "" : "  (" + Description + ")"); }
    }

    public static class Pcap
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool SetDllDirectory(string path);

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)] static extern int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);
        [DllImport("wpcap.dll")] static extern void pcap_freealldevs(IntPtr alldevs);
        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)] static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int toMs, StringBuilder errbuf);
        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)] static extern int pcap_compile(IntPtr p, IntPtr program, string filter, int optimize, uint netmask);
        [DllImport("wpcap.dll")] static extern int pcap_setfilter(IntPtr p, IntPtr program);
        [DllImport("wpcap.dll")] static extern void pcap_freecode(IntPtr program);
        [DllImport("wpcap.dll")] static extern int pcap_next_ex(IntPtr p, ref IntPtr header, ref IntPtr data);
        [DllImport("wpcap.dll")] static extern int pcap_datalink(IntPtr p);
        [DllImport("wpcap.dll")] static extern void pcap_close(IntPtr p);
        [DllImport("wpcap.dll")] static extern int pcap_setbuff(IntPtr p, int bytes);
        [DllImport("wpcap.dll")] static extern IntPtr pcap_geterr(IntPtr p);

        static bool loaded;

        public static string Load()
        {
            if (loaded) return null;
            string npcap = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
            if (Directory.Exists(npcap)) SetDllDirectory(npcap);
            try
            {
                IntPtr devs = IntPtr.Zero;
                pcap_findalldevs(ref devs, new StringBuilder(256));
                if (devs != IntPtr.Zero) pcap_freealldevs(devs);
                loaded = true;
                return null;
            }
            catch (DllNotFoundException)
            {
                return "Npcap is not installed. Install it from https://npcap.com and tick \"WinPcap API-compatible mode\".";
            }
        }

        public static List<PcapDevice> Devices()
        {
            var list = new List<PcapDevice>();
            IntPtr devs = IntPtr.Zero;
            var err = new StringBuilder(256);
            if (pcap_findalldevs(ref devs, err) != 0) throw new InvalidOperationException("pcap_findalldevs: " + err);
            // pcap_if: next, name, description, addresses, flags
            for (IntPtr d = devs; d != IntPtr.Zero; d = Marshal.ReadIntPtr(d))
            {
                list.Add(new PcapDevice
                {
                    Name = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(d, IntPtr.Size)),
                    Description = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(d, 2 * IntPtr.Size)),
                });
            }
            pcap_freealldevs(devs);
            return list;
        }

        // Captures TCP frames of one device until stop() returns true; every frame goes to onFrame (capture thread).
        public static void Run(string device, Action<CapturedFrame> onFrame, Func<bool> stop, Action<string> log)
        {
            var err = new StringBuilder(256);
            IntPtr p = pcap_open_live(device, 65536, 0, 100, err);
            if (p == IntPtr.Zero) { log("cannot open " + device + ": " + err); return; }
            try
            {
                pcap_setbuff(p, 32 << 20);
                IntPtr program = Marshal.AllocHGlobal(16);     // struct bpf_program { u_int bf_len; struct bpf_insn *bf_insns; }
                try
                {
                    if (pcap_compile(p, program, "tcp", 1, 0xFFFFFFFF) == 0)
                    {
                        pcap_setfilter(p, program);
                        pcap_freecode(program);
                    }
                }
                finally { Marshal.FreeHGlobal(program); }

                int link = pcap_datalink(p);
                IntPtr hdr = IntPtr.Zero, data = IntPtr.Zero;
                while (!stop())
                {
                    int r = pcap_next_ex(p, ref hdr, ref data);
                    if (r == 0) continue;               // timeout
                    if (r < 0) { log("capture stopped on " + device + ": " + Marshal.PtrToStringAnsi(pcap_geterr(p))); return; }
                    // struct pcap_pkthdr on Windows: timeval { long sec; long usec } (32-bit longs), u32 caplen, u32 len
                    long sec = (uint)Marshal.ReadInt32(hdr, 0), usec = (uint)Marshal.ReadInt32(hdr, 4);
                    int caplen = Marshal.ReadInt32(hdr, 8);
                    var bytes = new byte[caplen];
                    Marshal.Copy(data, bytes, 0, caplen);
                    onFrame(new CapturedFrame { LinkType = link, UnixMicros = sec * 1000000 + usec, Data = bytes });
                }
            }
            finally { pcap_close(p); }
        }
    }
}
