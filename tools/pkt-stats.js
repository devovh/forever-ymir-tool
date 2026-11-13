// Parsuje plik PKT 3.1 zapisany przez Ymira (format z PktFile.cs).
// Naglowek: "PKT" + ver(2) + ?(1) + build(4) + ?(4) + locale(40) + startTime(4) + startTick(4) + optLen(4) + opt
// Pakiet:   "SMSG"/"CMSG"(4) + conn(4) + tick(4) + extra(4) + len(4) + extra bytes + data(opcode 4 + payload)
const fs = require("fs");

const p = process.argv[2] || "C:/Users/devov/Desktop/regedit_70862/dumps/dump_1.60.1.70938_2026-11-13_14-02-23.pkt";
const b = fs.readFileSync(p);

if (b[0] !== 0x50 || b[1] !== 0x4b || b[2] !== 0x54) throw new Error("nie PKT");

const build = b.readInt32LE(6);
let locale = "";
for (let i = 14; i < 54; i++) { const c = b[i]; if (!c) break; locale += String.fromCharCode(c); }
let pos = 3 + 2 + 1 + 4 + 4 + 40;
const startTime = b.readUInt32LE(pos);
const startTick = b.readUInt32LE(pos + 4);
const optLen = b.readInt32LE(pos + 8);
pos += 12 + optLen;

console.log(`plik    : ${p}`);
console.log(`rozmiar : ${b.length} B`);
console.log(`build   : ${build}`);
console.log(`locale  : ${locale}`);
console.log(`start   : ${new Date(startTime * 1000).toISOString()}`);
console.log(`optLen  : ${optLen}`);

const counts = {};
let n = 0, cmsg = 0, smsg = 0, bad = 0;
const conns = new Set();
while (pos + 20 <= b.length) {
  const server = b[pos] === 0x53;
  const tag = b.slice(pos, pos + 4).toString("latin1");
  if (tag !== "SMSG" && tag !== "CMSG") { bad = pos; break; }
  const conn = b.readUInt32LE(pos + 4);
  const tick = b.readUInt32LE(pos + 8);
  const extra = b.readInt32LE(pos + 12);
  const len = b.readInt32LE(pos + 16);
  if (extra < 0 || len < 0 || pos + 20 + extra + len > b.length) { bad = pos; break; }
  const dataAt = pos + 20 + extra;
  const opcode = b.readUInt32LE(dataAt);
  counts[opcode] = (counts[opcode] || 0) + 1;
  conns.add(conn);
  if (server) smsg++; else cmsg++;
  n++;
  pos = dataAt + len;
}

console.log(`\npakietow: ${n}  (SMSG ${smsg}, CMSG ${cmsg})`);
console.log(`polaczenia: ${[...conns].join(", ")}`);
if (bad) console.log(`UWAGA: przerwano na bajcie ${bad} (niepelny pakiet na koncu - normalne przy zatrzymaniu)`);

const top = Object.entries(counts).sort((a, c) => c[1] - a[1]).slice(0, 12);
console.log(`\nnajczestsze opcody (${Object.keys(counts).length} roznych):`);
for (const [o, c] of top) console.log(`  0x${Number(o).toString(16).padStart(6, "0")}: ${c}`);
