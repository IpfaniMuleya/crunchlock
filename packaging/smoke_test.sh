#!/usr/bin/env bash
# CI smoke test of the bundled CLI: lock (with a JPEG) -> verify -> change password
# -> old password rejected -> unlock -> identical files. Run from the repo root
# after packaging/build.py. Set EXE=.exe on Windows.
set -euo pipefail
cli="./dist/crunchlock${EXE:-}"
export CRUNCHLOCK_PASSWORD=ci-smoke-test-passphrase
rm -rf smoke && mkdir -p smoke/in
seq 1 100000 > smoke/in/numbers.txt
cp README.md smoke/in/
python -c "from PIL import Image; Image.effect_mandelbrot((800, 600), (-2, -1.2, 1, 1.2), 100).convert('RGB').save('smoke/in/photo.jpg', quality=90)"
"$cli" genpass
"$cli" lock smoke/in -o smoke/t.clk -c best --recovery --pad --split 64K | tee smoke/lock.log
grep -q "JPEG photo(s) recompressed losslessly" smoke/lock.log
"$cli" verify smoke/t.clk.001 -q
CRUNCHLOCK_PASSWORD_NEW=ci-new-passphrase "$cli" rekey smoke/t.clk.001 -q
if "$cli" verify smoke/t.clk.001 -q; then echo "old password still works"; exit 1; fi
CRUNCHLOCK_PASSWORD=ci-new-passphrase "$cli" unlock smoke/t.clk.001 -o smoke/out -q
diff -r smoke/in smoke/out/in
echo "round trip OK"
