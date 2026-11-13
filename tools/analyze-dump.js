// Analiza zrzutu obrazu Wow.exe 70938: gdzie leza tablica locale i obiekt sesji.
// Czysty Node, bez zależności - czyta plik zrzutu z zachowanymi RVA.
//
// Użycie: node analyze-dump.js <dump.img> [sniff.pkt]
const fs = require("fs");

const dumpPath = process.argv[2] || "C:/Users/devov/Desktop/WoWSniff/dump_70938.img";
const pktPath = process.argv[3] || null;

const buf = fs.readFileSync(dumpPath);
console.log(`zrzut: ${dumpPath} (${(buf.length / 1048576).toFixed(1)} MB)`);

// --- nagłówek PE ---
const peOff = buf.readUInt32LE(0x3c);
const nsec = buf.readUInt16LE(peOff + 6);
const optSize = buf.readUInt16LE(peOff + 20);
const imageBase = buf.readBigInt64LE(peOff + 24 + 24);
const sizeOfImage = buf.readUInt32LE(peOff + 24 + 56);
const secStart = peOff + 24 + optSize;

const secs = [];
for (let i = 0; i < nsec; i++) {
  const o = secStart + i * 40;
  let name = "";
  for (let k = 0; k < 8; k++) {
    const c = buf[o + k];
    if (!c) break;
    name += String.fromCharCode(c);
  }
  secs.push({
    name,
    vsize: buf.readUInt32LE(o + 8),
    va: buf.readUInt32LE(o + 12),
    rawSize: buf.readUInt32LE(o + 16),
    rawPtr: buf.readUInt32LE(o + 20),
  });
}

console.log(`base 0x${imageBase.toString(16)}, SizeOfImage 0x${sizeOfImage.toString(16)}`);
for (const s of secs) console.log(`  ${s.name.padEnd(9)} VA=0x${s.va.toString(16).padStart(8)} vsize=0x${s.vsize.toString(16).padStart(8)}`);

// w zrzucie dane leza pod offsetem = RVA (plik ma rozmiar obrazu)
const inImage = (v) => v >= imageBase && v < imageBase + BigInt(sizeOfImage);
const sectionOf = (rva) => secs.find((s) => rva >= s.va && rva < s.va + s.vsize);
const rvaOf = (abs) => Number(abs - imageBase);

// --- 1. gdzie jest "enUS" ---
console.log("\n=== szukam napisow locale w obrazie");
const locales = ["enUS", "koKR", "frFR", "deDE", "zhCN", "zhTW", "esES", "esMX", "ruRU", "ptBR", "itIT"];
const localeHits = [];
for (const loc of locales) {
  const pat = Buffer.from(loc + "\0", "ascii");
  let idx = 0;
  while ((idx = buf.indexOf(pat, idx)) >= 0) {
    localeHits.push({ loc, rva: idx });
    idx += 1;
  }
}
for (const h of localeHits) {
  const s = sectionOf(h.rva);
  console.log(`  "${h.loc}" rva=0x${h.rva.toString(16)} sekcja=${s ? s.name : "?"}`);
}

// --- 2. kto wskazuje na te napisy ---
console.log("\n=== wskaźniki na napisy locale (8-bajtowe sloty w obrazie)");
const refs = [];
for (const h of localeHits) {
  const target = imageBase + BigInt(h.rva);
  const tgt = Buffer.alloc(8);
  tgt.writeBigInt64LE(target);
  let idx = 0;
  while ((idx = buf.indexOf(tgt, idx)) >= 0) {
    if (idx % 8 === 0) {
      const s = sectionOf(idx);
      refs.push({ slot: idx, loc: h.loc, sec: s ? s.name : "?" });
    }
    idx += 1;
  }
}
for (const r of refs.slice(0, 40)) console.log(`  slot rva=0x${r.slot.toString(16)} (${r.sec}) -> "${r.loc}"`);

// --- 3. tablica locale: sprawdz, czy sloty leza w serii co 8 lub co 16 bajtow ---
console.log("\n=== kandydaci na tablicę locale (kilka wskaźników pod rząd)");
const sortedSlots = refs.map((r) => r.slot).sort((a, b) => a - b);
const runs = [];
let run = [sortedSlots[0]];
for (let i = 1; i < sortedSlots.length; i++) {
  const gap = sortedSlots[i] - sortedSlots[i - 1];
  if (gap === 8 || gap === 16) run.push(sortedSlots[i]);
  else {
    if (run.length > 1) runs.push(run);
    run = [sortedSlots[i]];
  }
}
if (run.length > 1) runs.push(run);
if (runs.length === 0) console.log("  brak serii - struktura nie jest listą wskaźników");
for (const r of runs) console.log(`  seria od rva=0x${r[0].toString(16)} do 0x${r[r.length - 1].toString(16)} (${r.length} wpisów)`);

// --- 4. sesja: 40-bajtowe klucze o wysokiej entropii ---
console.log("\n=== kandydaci na klucz sesji (40 B, >=30 różnych bajtów) w .data");
const data = secs.find((s) => s.name === ".data");
if (data) {
  const start = data.va;
  const end = Math.min(data.va + data.vsize, buf.length);
  const cands = [];
  // szukamy miejsc, ktore wygladaja na klucz: 40 bajtow o duzej entropii
  for (let off = start; off + 40 <= end; off += 8) {
    const seen = new Set();
    for (let k = 0; k < 40; k++) seen.add(buf[off + k]);
    if (seen.size >= 34) cands.push({ rva: off, distinct: seen.size });
  }
  console.log(`  ${cands.length} kandydatów (pierwsze 10):`);
  for (const c of cands.slice(0, 10)) console.log(`    rva=0x${c.rva.toString(16)} distinct=${c.distinct}`);

  // sloty .data wskazujace w obraz - tam moze byc obiekt sesji z kluczem pod +0x48
  console.log("\n=== sloty .data wskazujące w obraz (obiekty, +0x48 = klucz?)");
  const slots = [];
  for (let off = start; off + 8 <= end; off += 8) {
    const v = buf.readBigInt64LE(off);
    if (!inImage(v)) continue;
    const rva = rvaOf(v);
    if (rva + 0x48 + 40 > buf.length) continue;
    const seen = new Set();
    for (let k = 0; k < 40; k++) seen.add(buf[rva + 0x48 + k]);
    if (seen.size >= 30) slots.push({ slotRva: off, ptrRva: rva, distinct: seen.size });
  }
  console.log(`  ${slots.length} slotów z kandydatem na klucz pod +0x48`);
  for (const s of slots.slice(0, 10)) {
    const key = buf.subarray(s.ptrRva + 0x48, s.ptrRva + 0x48 + 40).toString("hex");
    console.log(`    slot rva=0x${s.slotRva.toString(16)} -> ptr rva=0x${s.ptrRva.toString(16)} distinct=${s.distinct}`);
    console.log(`      key ${key}`);
  }
}

// --- 5. opcjonalnie: weryfikacja AES-GCM przez C# ---
if (pktPath) {
  console.log(`\n=== weryfikacja kryptograficzna na ${pktPath}`);
  console.log("(użyj SessionCheck.exe --session <dump> <pkt>)");
}
