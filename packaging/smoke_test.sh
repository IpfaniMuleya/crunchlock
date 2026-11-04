#!/usr/bin/env bash
# CI smoke test of the bundled CLI: lock (with a JPEG and a PNG) -> verify -> change
# password -> old password rejected -> add a file -> unlock -> identical files. Run from the repo root
# after packaging/build.py. Set EXE=.exe on Windows.
set -euo pipefail
cli="./dist/crunchlock${EXE:-}"
export CRUNCHLOCK_PASSWORD=ci-smoke-test-passphrase
rm -rf smoke && mkdir -p smoke/in
seq 1 100000 > smoke/in/numbers.txt
cp README.md smoke/in/
python -c "from PIL import Image; Image.effect_mandelbrot((800, 600), (-2, -1.2, 1, 1.2), 100).convert('RGB').save('smoke/in/photo.jpg', quality=90)"
# A PNG written with plain zlib, like most PNG tools do.
python -c "
import struct, zlib
c = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
w, h = 300, 200
rows = b''.join(b'\x01' + bytes(v for x in range(w) for v in (x % 7 * 30, y % 11 * 20, 99)) for y in range(h))
open('smoke/in/screen.png', 'wb').write(b'\x89PNG\r\n\x1a\n' + c(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + c(b'IDAT', zlib.compress(rows, 6)) + c(b'IEND', b''))
"
"$cli" genpass
"$cli" lock smoke/in -o smoke/t.clk -c best --recovery --pad --split 64K | tee smoke/lock.log
grep -q "JPEG photo(s) recompressed losslessly" smoke/lock.log
grep -q "PNG image(s) repacked losslessly" smoke/lock.log
"$cli" verify smoke/t.clk.001 -q
CRUNCHLOCK_PASSWORD_NEW=ci-new-passphrase "$cli" rekey smoke/t.clk.001 -q
if "$cli" verify smoke/t.clk.001 -q; then echo "old password still works"; exit 1; fi
echo "added later" > smoke/extra.txt
CRUNCHLOCK_PASSWORD=ci-new-passphrase "$cli" add smoke/t.clk.001 smoke/extra.txt -q
CRUNCHLOCK_PASSWORD=ci-new-passphrase "$cli" unlock smoke/t.clk.001 -o smoke/out -q
diff -r smoke/in smoke/out/in
diff smoke/extra.txt smoke/out/extra.txt
echo "round trip OK"
