#!/system/bin/sh
pm list packages -3 -f > /data/local/tmp/pkglist.txt
while IFS= read -r line; do
  apkpath=$(echo "$line" | sed 's/package://;s/=[^=]*$//')
  pkgname=$(echo "$line" | sed 's/.*=//')
  result=$(sha256sum "$apkpath" 2>/dev/null)
  hash=$(echo "$result" | cut -d' ' -f1)
  if [ -n "$hash" ]; then
    echo "$hash  $apkpath  $pkgname"
  fi
done < /data/local/tmp/pkglist.txt
rm -f /data/local/tmp/pkglist.txt
