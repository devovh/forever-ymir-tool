# Ymir Tool

A small Windows app around **Ymir**, the sniffer we use on the WoW Classic Forever beta:

1. **Patch Ymir** makes a copy of Ymir for a new client build.
2. **Record** starts and stops Ymir and lists your sniffs.
3. **Viewer** opens a sniff (`.pkt`), even while Ymir is still recording it.

It needs nothing installed: one `YmirTool.exe`, Windows 10 or 11. Languages: English, Español, Русский (top right).

## 1. Patch Ymir

Ymir only works with the client build it was made for. When Blizzard updates the beta client, it needs to know three
addresses inside the new `WowB.exe`. This tab finds them and writes `regedit_<build>.exe` next to the original `regedit.exe`.

- **Known builds** (70170, 70205, 70235 and every build you confirmed before) are filled in at once: just press **Create patched Ymir**.
- **A new build:** start the game, log in to the character screen, press **Find addresses**. Each address gets a check:
  - green **OK**: confirmed (the language names are there / the number is a language / the session key is there),
  - orange **Unconfirmed**: found, but the session key is not there yet (log in, search again),
  - red **FAILED**: not found; don't create Ymir, ask for help with the log below the table.
  When all three are green the build is remembered, so next time it's instant.
- The original `regedit.exe` is never changed. A Ymir that is not the one this tool knows is refused.
- The game is only **read**, never written.

## 2. Record

**Recorder:** choose **Ymir** (the copy made in tab 1 for your client build) or **Forever Sniffer**, our own sniffer
(`sniffer/`, works with any client build without patching). For Forever Sniffer, **Browse** picks where `ForeverSniffer.exe`
is (by default the one next to `YmirTool.exe`); the sniffs go to the `dumps` folder next to it. **Close the game if the recording
goes wrong** starts it with `--strict` (like Ymir's own safety stop).

A checklist shows what Ymir needs, each with a ✔ or ✖:

| Item | If it is ✖ |
|---|---|
| Npcap | Install it from https://npcap.com and tick **"WinPcap API-compatible mode"**. |
| Capture adapter | Start Ymir once by hand and choose your network adapter in its window. |
| Ymir for your client build | Make it in tab 1. |

Then:

1. Leave **"Delete the game's Cache folder"** on (Ymir's own advice: the client then asks the server for everything again, so the sniff has more data). It only works while the game is closed.
2. Press **Start Ymir**, then start the game and play.
3. Close the game when you are done: Ymir saves the sniff and closes by itself a few seconds later. **Stop Ymir** is only for when you want to end early.

While it records, the status line shows the sniff's name and size. Below is the list of your sniffs (newest first). Double-click one to open it in the viewer.

## 3. Viewer

- **Open sniff** (or drag a `.pkt` onto the window). With **Follow live** on, new packets appear while Ymir records; **Back to live** jumps to the newest packet.
- **Filter** by opcode name (`QUEST`, `GOSSIP`...) or number (`5D0000`), and by direction. Blue rows are sent by the client.
- **Summary by opcode**: how often each opcode appears and its sizes. Double-click a row to filter to it.
- **Search packet contents**: text (any case, e.g. a creature name) or hex bytes (`8B 02 FF`). **Next** / **Previous** (or Enter / Shift+Enter) jump between matches; the match is marked with `*` in the hex view.
- **Export list (CSV)** saves the packets the filter shows. **Copy hex** and **Save packet** take the selected packet.

## Good to know

- Sniffs contain private data (your account, character names, chat). Share them only with people you trust.
- Settings and the builds it learned are in `%APPDATA%\YmirTool`.
- Build it yourself: run `build.cmd` (uses the C# compiler that comes with Windows; output `dist\YmirTool.exe`).
- Check it: `YmirTool.exe --selftest report.txt <70124 dump> <70205 dump> <regedit.exe> <regedit_70235.exe> <sniff.pkt>`.

## License

GPL-3.0, see [LICENSE](LICENSE). Ymir itself is not part of this repository.

## Finding the three addresses on a new build

The fingerprint search in `data/fingerprints.txt` was made from builds 70124–70291. It stops being decisive as soon as
the client's locale table changes shape: on 70938 the table grew from 4 entries to 11, every spot tied with its runner-up
(`locale_index 4/46`, `session 3/132`) and the search picked an arbitrary candidate each run. Two of the three addresses
can be found by **structure** instead, which needs no fingerprint and no table:

**`locale_table`** — the client keeps the locale names in alphabetical order behind a run of qwords. Walk `.data` and
`.rdata` for 9 consecutive qwords pointing at `enUS koKR frFR deDE zhCN zhTW esES esMX ruRU`, in that order. Nothing
else in the image has that shape. (`Finder.FindLocaleTables`.)

**`locale_index`** — it is *not* a lone number in `.data`. Next to the names sits a table of records, `0x18` bytes each:
`[qword name pointer][u32 index][u32 flags]`. Ymir reads the `u32` right after the `enUS` record's name pointer — `0`
for an English client. Find the record, take `+8`. (`Finder.FindLocaleIndexByRecords`.)

**`session`** — take it from **Forever Sniffer**: on a build it does not know, the sniffer searches the client's memory
itself and prints the answer, e.g.

```
session key found: pointer at image RVA 0x4b69948, key at +0x48 (build 70938)
```

The key lives 40 bytes into the object that slot points at.

### Build 70938 (Forever 1.60.1)

| address | value | how it was confirmed |
|---|---|---|
| locale_table | `0x3c02710` | 11 locale pointers in `.rdata`, verified 227/227 |
| locale_index | `0x483f908` | record table at `0x483f900`, index `0` = enUS |
| session | `0x4b69948` | Forever Sniffer's own search |

Confirmed on the live client: a patched Ymir printed `Allowed build: 1.60.1.70938`, `Detected locale: enUS`, and wrote
30 769 packets into a `.pkt` whose header carries build `70938`.

### Offline check

`tools/` has the scripts used to work this out. With a memory dump of the running client (`tools/dump-image.ps1` dumps
the module image, `tools/dump-heap.ps1` the heap regions around it):

```
node tools/analyze-dump.js       # locale names, pointer refs, key candidates
node tools/pkt-stats.js <sniff>  # header, packet count, opcodes of a .pkt
node tools/find-locale-index2.js # locale record table in a dump
```
