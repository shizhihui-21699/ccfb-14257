#!/usr/bin/env bash
# End-to-end tests for the deniable-encryption container.
# Each section maps to a claim made in docs/DESIGN.md.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DENC="$ROOT/build/denc"
ANZ="$ROOT/build/denc-forensic"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

pass=0; fail=0
check() { # check <description> <condition-command...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS  $desc"; pass=$((pass+1));
  else echo "FAIL  $desc"; fail=$((fail+1)); fi
}
DD() { dd if=/dev/urandom of="$1" bs=1024 count="$2" 2>/dev/null; }

echo "== crypto known-answer tests =="
"$ROOT/build/selftest"; [ $? -eq 0 ] && pass=$((pass+1)) || fail=$((fail+1))

printf 'decoy-password' > pw.txt
DD decoy1.bin 100
DD decoy2.bin 200
DD secret.bin 80

echo "== container creation =="
"$DENC" create -s 8M -p pw.txt outer.denc >/dev/null
check "outer-only container creates" test -f outer.denc
"$DENC" create -s 8M -H 2M -p pw.txt vault.denc >/dev/null
check "outer+hidden container creates" test -f vault.denc
check "container size is fixed" bash -c "[ $(stat -f%z vault.denc) -eq 8388608 ]"

echo "== outer file operations =="
"$DENC" open -p pw.txt vault.denc put decoy1.bin report.docx >/dev/null
"$DENC" open -p pw.txt vault.denc put decoy2.bin notes.txt >/dev/null
"$DENC" open -p pw.txt vault.denc get report.docx r1.bin >/dev/null
check "outer file round-trips byte-identical" cmp decoy1.bin r1.bin
check "outer lists both decoy files" bash -c \
  "test \$($DENC open -p pw.txt vault.denc ls | wc -l) -eq 2"
"$DENC" open -p pw.txt vault.denc rm notes.txt >/dev/null
check "outer rm removes a file" bash -c \
  "test \$($DENC open -p pw.txt vault.denc ls | wc -l) -eq 1"

echo "== hidden volume isolation =="
"$DENC" open --hidden -p pw.txt vault.denc put secret.bin covert.dat >/dev/null
"$DENC" open --hidden -p pw.txt vault.denc get covert.dat hs.bin >/dev/null
check "hidden file round-trips byte-identical" cmp secret.bin hs.bin
check "outer cannot see hidden file" bash -c \
  "! $DENC open -p pw.txt vault.denc ls | grep -q covert"
check "hidden cannot see outer file" bash -c \
  "! $DENC open --hidden -p pw.txt vault.denc ls | grep -q report"

echo "== hidden protection against outer overwrites =="
DD big.bin 1500
"$DENC" open -p pw.txt vault.denc put big.bin big.dat >/dev/null
"$DENC" open --hidden -p pw.txt vault.denc get covert.dat hs2.bin >/dev/null
check "hidden data survives aggressive outer fill" cmp secret.bin hs2.bin
DD huge.bin 4000
if "$DENC" open -p pw.txt vault.denc put huge.bin huge.dat 2>/dev/null; then
  echo "FAIL  outer overfill must be rejected"; fail=$((fail+1))
else
  echo "PASS  outer overfill rejected (hidden tail protected)"; pass=$((pass+1))
fi
"$DENC" open --hidden -p pw.txt vault.denc get covert.dat hs3.bin >/dev/null
check "hidden still intact after rejected overfill" cmp secret.bin hs3.bin
"$DENC" open -p pw.txt vault.denc ls >/dev/null
check "outer stays consistent after rejected overfill" test $? -eq 0

echo "== multi-transaction large files =="
DD multi.bin 600
"$DENC" open -p pw.txt vault.denc put multi.bin multi.dat >/dev/null
"$DENC" open -p pw.txt vault.denc get multi.dat multi.back >/dev/null
check "large multi-WAL file round-trips" cmp multi.bin multi.back

echo "== crash recovery (atomicity) =="
for stage in 1 2 3; do
  cp vault.denc "crash$stage.denc"
  DENC_CRASH_AT="$stage:1" "$DENC" open -p pw.txt "crash$stage.denc" \
      put decoy1.bin "cf$stage.dat" >/dev/null 2>&1 || true
  check "stage-$stage crash: container reopens" \
    "$DENC" open -p pw.txt "crash$stage.denc" ls
done
# redo evidence: crash at the FINAL (inode) commit must expose the file.
cp vault.denc redo.denc
DD tiny.bin 4
DENC_CRASH_AT="2:3" "$DENC" open -p pw.txt redo.denc put tiny.bin \
    tiny.dat >/dev/null 2>&1 || true
"$DENC" open -p pw.txt redo.denc get tiny.dat tiny.back >/dev/null 2>&1
check "redo replay recovers committed file contents" cmp tiny.bin tiny.back

echo "== mtime pinning =="
before=$(stat -f%m vault.denc)
"$DENC" open -k -p pw.txt vault.denc put decoy1.bin pinned.docx >/dev/null
after=$(stat -f%m vault.denc)
check "-k preserves container mtime" bash -c "[ $before -eq $after ]"

echo "== password change covers both volumes =="
printf 'new-secret-pw' > newpw.txt
"$DENC" chpass -p pw.txt -P newpw.txt vault.denc >/dev/null
check "old password rejected after chpass" bash -c \
  "! $DENC open -p pw.txt vault.denc ls 2>/dev/null"
check "new password opens outer" \
  "$DENC" open -p newpw.txt vault.denc ls
check "new password opens hidden" \
  "$DENC" open --hidden -p newpw.txt vault.denc ls

echo "== forensic analyzer: cannot prove the hidden volume =="
"$ANZ" audit vault.denc > audit.txt 2>&1
check "audit reports no proof of a second volume" \
  grep -q "CANNOT be" audit.txt
check "audit sees full entropy across the image" \
  grep -q "entropy=8.0000" audit.txt
check "audit finds no all-zero sectors" \
  grep -q "all-zero 4K sectors: 0" audit.txt

cp vault.denc snap0.denc
"$DENC" open --hidden -p newpw.txt vault.denc put secret.bin c2.dat >/dev/null
cp vault.denc snap1.denc
"$ANZ" diff snap0.denc snap1.denc > diff.txt 2>&1
check "snapshot diff cannot distinguish hidden write from random" \
  grep -q "not proof either way" diff.txt

echo
echo "=================="
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
