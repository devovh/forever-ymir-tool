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
