// Szuka locale_index w zrzucie 70938.
//
// Co wiemy: locale_index to int32 - numer locale w tablicy (0=enUS ... 11=itIT).
// Ymir czyta go, by wiedzieć, które locale obsługuje. Klient stoi na enUS, więc wartość to najpewniej 0.
//
// Filtr: bierzemy int32 o wartości 0..32 z .data, ale tylko tam, gdzie w pobliżu (w promieniu 0x40)
// leży coś, co wygląda na dane locale: albo wskaźnik na tablicę locale, albo na napis locale,
// albo sama tablica jest adresowana z tej okolicy.
const fs = require("fs");

const dump = fs.readFileSync("C:/Users/devov/Desktop/WoWSniff/dump_70938_live.img");

const pe = dump.readUInt32LE(0x3c);
const nsec = dump.readUInt16LE(pe + 6);
const opt = dump.readUInt16LE(pe + 20);
const base = dump.readBigInt64LE(pe + 24 + 24);
const size = dump.readUInt32LE(pe + 24 + 56);

const secs = [];
for (let i = 0; i < nsec; i++) {
  const o = pe + 24 + opt + i * 40;
  let n = "";
  for (let k = 0; k < 8; k++) {
    const c = dump[o + k];
    if (!c) break;
    n += String.fromCharCode(c);
  }
  secs.push({ n, rva: dump.readUInt32LE(o + 12), vs: dump.readUInt32LE(o + 8) });
}
const secOf = (rva) => secs.find((s) => rva >= s.rva && rva < s.rva + s.vs);
const ds = secs.find((s) => s.n === ".data");
const rd = secs.find((s) => s.n === ".rdata");

const TABLE = 0x3c02710;
const LOCALES = ["enUS", "koKR", "frFR", "deDE", "zhCN", "zhTW", "esES", "esMX", "ruRU", "ptBR", "itIT"];

// adresy napisów locale (z tablicy + z .rdata)
const localeAddrs = new Set();
for (let k = 0; k < 12; k++) {
  const v = dump.readBigInt64LE(TABLE + k * 8);
  if (v !== 0n) localeAddrs.add(Number(v - base));
}
for (const loc of LOCALES) {
  const pat = Buffer.from(loc + "\0", "ascii");
  let i = 0;
  while ((i = dump.indexOf(pat, i)) >= 0) {
    localeAddrs.add(i);
    i += 1;
  }
}
console.log(`adresów napisów locale: ${localeAddrs.size}`);

// kandydaci: int32 0..32 w .data, z "sasiedztwem locale" w promieniu 0x40
const R = 0x40;
const cands = [];
const end = Math.min(ds.rva + ds.vs, dump.length);
for (let off = ds.rva; off + 4 <= end; off += 4) {
  const v = dump.readInt32LE(off);
  if (v < 0 || v > 32) continue;

  let near = null;
  // sprawdz 8-bajtowe sloty w promieniu: czy wskazuja na tablice albo na napis locale
  for (let s = Math.max(ds.rva, off - R); s + 8 <= Math.min(end, off + R + 8); s += 8) {
    if (s % 8 !== 0) continue;
    const p = dump.readBigInt64LE(s);
    if (p < base || p >= base + BigInt(size)) continue;
    const pr = Number(p - base);
    if (pr === TABLE) { near = `wskaźnik na TABLICĘ (slot 0x${s.toString(16)})`; break; }
    if (localeAddrs.has(pr)) { near = `wskaźnik na napis locale (slot 0x${s.toString(16)})`; break; }
  }
  if (near) cands.push({ off, v, near });
}

console.log(`\n=== kandydaci z sasiedztwem locale (promień 0x${R.toString(16)}): ${cands.length}`);
for (const c of cands.slice(0, 40)) {
  console.log(`  slot 0x${c.off.toString(16)} (${(secOf(c.off) || {}).n}) = ${c.v}   <- ${c.near}`);
}
if (cands.length > 40) console.log(`  ... i ${cands.length - 40} więcej`);

// osobno: kandydaci wartosci 0 (enUS) - najbardziej prawdopodobne dla tego klienta
const zeros = cands.filter((c) => c.v === 0);
console.log(`\n=== z tego wartość 0 (enUS): ${zeros.length}`);
for (const c of zeros.slice(0, 20)) console.log(`  0x${c.off.toString(16)}  <- ${c.near}`);
