#!/usr/bin/env node
/**
 * patch-ymir.js — samodzielne patchowanie Ymira (Forever beta) na inny build klienta.
 *
 * Reimplementacja src/YmirPatcher.cs + src/Finder.cs z forever-ymir-tool,
 * bez GUI i bez .NET — wystarczy Node.
 *
 * Użycie:
 *   node patch-ymir.js <ymir.exe> --build 70888 \
 *        --locale-index 0x5f9fbd4 --locale-table 0x497a440 --session 0x5ffd0f8
 *
 *   node patch-ymir.js <ymir.exe> --check
 *        (tylko sprawdza, czy plik jest oryginałem 70124)
 *
 * Trzy adresy (locale-index, locale-table, session) to RVA wewnątrz WowB.exe
 * dla danego builda — bierzesz je z YmirTool (zakładka Patch Ymir, "Find addresses")
 * albo z tabeli KnownBuilds, jeśli build jest znany.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ---------------------------------------------------------------- tabela z YmirPatcher.cs
const ORIGINAL_BUILD = 70124;
const ORIGINAL_SHA256 = "97d0bd72ed78b6176e4011faa7da3c02775ec504eb0c7f8eec280d23e1058e5e";

function spot(fileOffset, kind, hex, valueAt, text, newOpcode = 0) {
  return { fileOffset, kind, original: Buffer.from(hex, "hex"), valueAt, text, newOpcode };
}

const SPOTS = [
  spot(0x11a331, "build", "BAEC110100", 1, "mov edx, build (build text)"),
  spot(0x11a5b9, "build", "BAEC110100", 1, "mov edx, build (.pkt header)"),
  spot(0x11ba3a, "build", "3DEC110100", 1, "cmp eax, build (WowB.exe version check)"),
  spot(0x11ce45, "build", "BAEC110100", 1, "mov edx, build (build text)"),
  spot(0x11d2bd, "build", "BAEC110100", 1, "mov edx, build (build text)"),
  spot(0x11c206, "locale_index", "4881C2C40BFA05", 3, "add rdx, locale index"),
  spot(0x11c222, "locale_table", "488D940AC0F39604", 4, "lea rdx, [rdx+rcx+locale table]"),
  spot(0x11e2a0, "session", "4881C208E1FF05", 3, "add rdx, session key object"),

  // od klienta 70291 przesunęły się grupy opcodów (serwer 0x4D -> 0x4E, klient 0x45 -> 0x46, main 0x46 -> 0x47)
  spot(0x11e989, "opcode", "81F90E004D00", 2, "cmp ecx, SMSG_COMPRESSED_PACKET", 0x4e000e),
  spot(0x11e991, "opcode", "81F90D004D00", 2, "cmp ecx, SMSG_MULTIPLE_PACKETS", 0x4e000d),
  spot(0x11ebc2, "opcode", "81FF08004D00", 2, "cmp edi, SMSG_CONNECT_TO", 0x4e0008),
  spot(0x11eff6, "opcode", "81FF00004D00", 2, "cmp edi, SMSG_AUTH_CHALLENGE", 0x4e0000),
  spot(0x11f037, "opcode", "81C7FCFFB2FF", 2, "add edi, -SMSG_ENTER_ENCRYPTED_MODE", 0xffb1fffc),
  spot(0x11f261, "opcode", "81FF0C004600", 2, "cmp edi, main group 0x0C", 0x47000c),
  spot(0x11f26d, "opcode", "81FFF1014600", 2, "cmp edi, main group 0x1F1", 0x4701f2),
  spot(0x11f87a, "opcode", "8D8F0000BBFF", 2, "lea ecx, [rdi - client connection group]", 0xffba0000),
  spot(0x11f96b, "opcode", "81FF0C004600", 2, "cmp edi, main group 0x0C", 0x47000c),
];

// ---------------------------------------------------------------- tabela z Finder.cs
const KNOWN_BUILDS = {
  70124: { localeIndex: 0x5fa0bc4, localeTable: 0x496f3c0, session: 0x5ffe108 },
  70170: { localeIndex: 0x5ef4484, localeTable: 0x48d43c0, session: 0x5f519d8 },
  70205: { localeIndex: 0x5ef5804, localeTable: 0x48d53c0, session: 0x5f52d08 },
  70235: { localeIndex: 0x5f06fc4, localeTable: 0x48e33c0, session: 0x5f644d8 },
  70245: { localeIndex: 0x5f08004, localeTable: 0x48e43c0, session: 0x5f65518 },
  70291: { localeIndex: 0x5f9fbd4, localeTable: 0x497a440, session: 0x5ffd0f8 },
};

// ---------------------------------------------------------------- reszta logiki

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Spoty build, ktore starsze patche nadpisaly NOP-ami - nie ma tam juz numeru builda
// spoty build, ktore starsze wersje narzedzia zamienialy na NOP-y (0x11a331, 0x11ce45) - tylko do informacji

// build, od ktorego istnieja przesuniete grupy opcodow
const OPCODE_BUILD = 70291;

/** null = plik da sie patchowac, w przeciwnym razie powod odmowy */
function checkSource(data) {
  if (data.length < 0x120000) return "plik za maly";
  for (const s of SPOTS) {
    if (s.fileOffset + s.original.length > data.length) return "plik za maly";
    const prolog = s.original.subarray(0, s.valueAt);
    // spoty build nadpisane NOP-ami: sprawdzamy tylko, czy nie ma tam smieci
    // Spoty "build": pierwszy bajt to rozkaz (BA / 3D), reszta to numer builda. Kazdy patch tego narzedzia wstawia tam
    // swoj numer, wiec nie mozna zadac konkretnej wartosci - sprawdzamy tylko rozkaz (albo NOP-y po starszym patchu).
    if (s.kind === "build") {
      const first = data[s.fileOffset];
      if (first !== s.original[0] && first !== 0x90) {
        return `nieoczekiwane bajty pod 0x${s.fileOffset.toString(16)} (${s.text})\n` +
               `  jest: ${data.subarray(s.fileOffset, s.fileOffset + 5).toString("hex").match(/../g).join(" ")}`;
      }
      continue;
    }
    for (let i = 0; i < prolog.length; i++) {
      if (data[s.fileOffset + i] !== prolog[i]) {
        return `nieoczekiwane bajty pod 0x${s.fileOffset.toString(16)} (${s.text})\n` +
               `  jest:       ${data.subarray(s.fileOffset, s.fileOffset + prolog.length).toString("hex").match(/../g).join(" ")}\n` +
               `  oczekiwane: ${prolog.toString("hex").match(/../g).join(" ")}`;
      }
    }
  }
  return null;
}

/** adresy zapisane aktualnie w pliku */
function readCurrent(data) {
  const out = {};
  for (const s of SPOTS) {
    if (s.kind === "build" || s.kind === "opcode") continue;
    out[s.kind] = data.readUInt32LE(s.fileOffset + s.valueAt);
  }
  return out;
}

/** numer builda zapisany aktualnie w pliku (0 = nie da sie odczytac) */
function readBuild(data) {
  for (const s of SPOTS) {
    if (s.kind !== "build") continue;
    const v = data.readUInt32LE(s.fileOffset + s.valueAt);
    if (v > 60000 && v < 100000) return v;
  }
  return 0;
}

/** null, jesli plik da sie przepatchowac na dany build */
function checkTarget(data, build) {
  const current = readBuild(data);
  if (current === 0) return "nie da sie odczytac numeru builda z tego pliku";
  if (current > build) return `ten Ymir jest juz buildem ${current} - mozna tylko w gore (na nowszy klient)`;
  if (build < OPCODE_BUILD && current >= OPCODE_BUILD)
    return `ten Ymir ma juz grupy opcodow 70291+ i nie da sie wrocic do builda ${build}`;
  return null;
}

function patch(source, build, addrs) {
  const why = checkSource(source);
  if (why) throw new Error(why);

  const d = Buffer.from(source);
  const changes = [];
  const current = readBuild(source);

  for (const s of SPOTS) {
    if (s.kind === "opcode" && build < OPCODE_BUILD) continue;
    const value = s.kind === "opcode" ? s.newOpcode
                : s.kind === "build" ? build
                : addrs[s.kind];
    if (value === undefined || value === null) throw new Error(`brak adresu dla "${s.kind}"`);

    const at = s.fileOffset + s.valueAt;
    const before = d.readUInt32LE(at);
    d.writeUInt32LE(value >>> 0, at);
    changes.push({ at, kind: s.kind, text: s.text, before, after: value >>> 0 });
  }

  // jak patch_ymir.py: POPRZEDNI numer builda musi zniknac w calym pliku
  if (current === 0) return { data: d, changes, current };
  const old = Buffer.alloc(4);
  old.writeUInt32LE(current);
  for (let i = 0; i + 4 <= d.length; i++) {
    if (d[i] === old[0] && d[i + 1] === old[1] && d[i + 2] === old[2] && d[i + 3] === old[3]) {
      throw new Error(`build ${current} nadal obecny pod 0x${i.toString(16)} — patch niekompletny`);
    }
  }

  return { data: d, changes, current };
}

function outputPath(source, build) {
  const dir = path.dirname(source);
  const base = path.basename(source, path.extname(source));
  return path.join(dir, `${base}_${build}.exe`);
}

// ---------------------------------------------------------------- CLI

function usage() {
  console.log(`patch-ymir.js — patchowanie Ymira (Forever) na inny build klienta

  node patch-ymir.js <ymir.exe> --check
  node patch-ymir.js <ymir.exe> --build 70888 --locale-index 0x5f9fbd4 --locale-table 0x497a440 --session 0x5ffd0f8

  --build         numer builda klienta (np. 70888)
  --locale-index  RVA locale_index w WowB.exe
  --locale-table  RVA locale_table w WowB.exe
  --session       RVA obiektu klucza sesji w WowB.exe
  --check         tylko sprawdź, czy plik to oryginał 70124
  --known         wypisz znane buildy z gotowymi adresami

Adresy bierzesz z YmirTool -> zakładka "Patch Ymir" -> "Find addresses".
Oryginał Ymir musi mieć SHA256 ${ORIGINAL_SHA256}.`);
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) return usage();

  const file = argv[0];
  const opt = (name, def) => {
    const i = argv.indexOf(name);
    return i === -1 ? def : argv[i + 1];
  };
  const num = (v) => (typeof v === "string" ? Number(v.startsWith("0x") ? BigInt(v) : v) : v);

  if (argv.includes("--known")) {
    console.log("znane buildy (Ymir original = 70124):\n");
    console.log("build   locale_index  locale_table  session      flaga");
    for (const [b, a] of Object.entries(KNOWN_BUILDS)) {
      console.log(`${b}  0x${a.localeIndex.toString(16).padEnd(12)}  0x${a.localeTable.toString(16).padEnd(12)}  0x${a.session.toString(16).padEnd(10)} ${b === "70124" ? "(oryginał)" : ""}`);
    }
    return;
  }

  if (!fs.existsSync(file)) {
    console.error(`nie ma pliku: ${file}`);
    process.exit(1);
  }

  const source = fs.readFileSync(file);
  const hash = sha256(source);

  console.log(`plik:   ${file}`);
  console.log(`rozmiar: ${source.length} B`);
  console.log(`SHA256: ${hash}`);

  if (argv.includes("--check")) {
    const why = checkSource(source);
    if (why) {
      console.log(`\nWYNIK: ten plik nie jest Ymirowana wersja, ktora to narzedzie zna\n${why}`);
      process.exit(2);
    }
    const b = readBuild(source);
    const cur = readCurrent(source);
    const orig = hash === ORIGINAL_SHA256;
    console.log(`\nWYNIK: plik da sie patchowac`);
    console.log(orig ? "  to jest ORYGINAL 70124" : `  to jest juz SPATCHOWANA kopia, build ${b}`);
    console.log(`  locale_index  0x${cur.locale_index.toString(16)}`);
    console.log(`  locale_table  0x${cur.locale_table.toString(16)}`);
    console.log(`  session       0x${cur.session.toString(16)}`);
    return;
  }

  const build = num(opt("--build"));
  if (!build) {
    console.error("\nbrak --build (albo użyj --check)");
    usage();
    process.exit(1);
  }

  const known = KNOWN_BUILDS[build] || {};
  const addrs = {
    locale_index: num(opt("--locale-index", known.localeIndex)),
    locale_table: num(opt("--locale-table", known.localeTable)),
    session: num(opt("--session", known.session)),
  };

  const missing = Object.entries(addrs).filter(([, v]) => v === undefined).map(([k]) => k);
  if (missing.length) {
    console.error(`\nbrak adresów: ${missing.join(", ")}`);
    console.error("podaj je przez --locale-index / --locale-table / --session");
    process.exit(1);
  }

  console.log(`\nbuild docelowy: ${build}`);
  for (const [k, v] of Object.entries(addrs)) console.log(`  ${k.padEnd(13)} 0x${v.toString(16)}`);

  const cannot = checkTarget(source, build);
  if (cannot) {
    console.error(`\nBŁĄD: ${cannot}`);
    process.exit(4);
  }

  let result;
  try {
    result = patch(source, build, addrs);
  } catch (e) {
    console.error(`\nBŁĄD: ${e.message}`);
    console.error("\nPlik nie został zmieniony.");
    process.exit(3);
  }

  console.log(`\nprzepatchowano z builda ${result.current || "?"} na ${build}`);
  console.log(`zmienione miejsca (${result.changes.length}):`);


  for (const c of result.changes) {
    console.log(`  0x${c.at.toString(16).padEnd(9)} ${c.kind.padEnd(13)} 0x${c.before.toString(16)} -> 0x${c.after.toString(16)}   ${c.text}`);
  }

  const out = outputPath(file, build);
  fs.writeFileSync(out, result.data);
  console.log(`\nzapisano: ${out}`);
  console.log(`SHA256:   ${sha256(result.data)}`);
  console.log("\nGotowe. Oryginał nietknięty.");
}

if (require.main === module) main();

module.exports = { SPOTS, KNOWN_BUILDS, checkSource, checkTarget, readBuild, readCurrent, patch, sha256, ORIGINAL_SHA256, OPCODE_BUILD };
