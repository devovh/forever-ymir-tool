// Buduje SZTUCZNY "oryginał" do testu patchera: plik wypelniony zerami,
// w ktorych SPOTS maja dokladnie te bajty, ktorych oczekuje patch-ymir.js.
// To NIE jest prawdziwy Ymir — sluzy tylko do sprawdzenia logiki.
const fs = require("fs");
const { SPOTS } = require("./patch-ymir.js");

const SIZE = 0x120000;
const buf = Buffer.alloc(SIZE, 0x00);
for (const s of SPOTS) s.original.copy(buf, s.fileOffset);

// stary numer builda zostaw tez poza spotami, zeby sprawdzic kontrole "70124 still present"
const tail = Buffer.alloc(4); tail.writeUInt32LE(70124);
tail.copy(buf, 0x100);

fs.writeFileSync(process.argv[2] || "test-original.exe", buf);
console.log(`zapisano ${process.argv[2] || "test-original.exe"} (${SIZE} B, atrapa)`);
