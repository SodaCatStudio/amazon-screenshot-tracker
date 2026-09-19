#!/usr/bin/env bash
set -u
fail=0
for f in $(find templates -name '*.html'); do
  case "$f" in templates/partials/*) continue ;; esac
  n=$(grep -c '<!DOCTYPE' "$f")
  if [ "$n" -gt 1 ]; then echo "DUPLICATED: $f has $n copies (expected 1)"; fail=1; continue; fi
  [ "$n" -eq 0 ] && continue
  tail -c 200 "$f" | grep -q '</html>' || { echo "TRUNCATED: $f does not end with </html>"; fail=1; }
done
if [ "$fail" -ne 0 ]; then
  echo; echo "Commit blocked. Re-copy the file(s) with a replacing write (tar xzf, or cp) — never '>>'."
  exit 1
fi
echo "templates OK: one complete document per page"
