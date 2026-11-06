#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/apk
python scripts/prepare.py
bash gradlew --no-daemon :lab:assembleDebug :helper:assembleDebug :sample:assembleDebug -PsampleVersion=1 -PsampleSigner=a
cp lab/build/outputs/apk/debug/lab-debug.apk results/apk/security-lab.apk
cp helper/build/outputs/apk/debug/helper-debug.apk results/apk/lab-helper.apk
cp sample/build/outputs/apk/debug/sample-debug.apk results/apk/sample-v1-a.apk
bash gradlew --no-daemon :sample:assembleDebug -PsampleVersion=2 -PsampleSigner=b
cp sample/build/outputs/apk/debug/sample-debug.apk results/apk/sample-v2-b.apk
bash gradlew --no-daemon :sample:assembleDebug -PsampleVersion=2 -PsampleSigner=a
cp sample/build/outputs/apk/debug/sample-debug.apk results/apk/sample-v2-a.apk
# Public information only. Private fixtures remain outside results/.
cp .lab-secrets/ca.pem results/apk/laboratory-ca.pem
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -n "$sdk" ]; then
  signer=$(find "$sdk/build-tools" -name apksigner | sort -V | tail -1)
  for apk in results/apk/*.apk; do "$signer" verify --verbose --print-certs "$apk" > "$apk.cert.txt"; done
fi
python scripts/inspect_apks.py --sdk "$sdk"
