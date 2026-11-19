#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FLUTTER="${FLUTTER:-flutter}"
OUT="$ROOT/tests/fixtures"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

cd "$WORK"
"$FLUTTER" create --org com.archaeologist --project-name archaeologist_demo \
  --platforms android -t app demo >/dev/null
cd demo
rm -rf lib test
cp -r "$ROOT/examples/demo_app/lib" lib
cp "$ROOT/examples/demo_app/pubspec.yaml" pubspec.yaml
cp -r "$ROOT/examples/demo_app/android/." android/

P() { printf '%s' "$@"; }
STRIPE="$(P sk_ live_ FakeArchaeologistDemo0000)"
AWS_ID="$(P AK IA ARCHAEOLOGIST123)"
AWS_SECRET="$(P wJalrXUtnFEMI /K7MDENG/ bPxRfiCYDEMOKEY00000)"
GOOGLE="$(P AI za SyFAKEArchaeologistDemoKey123456789)"
SB_URL="https://abcdefghijklmnopqrst.supabase.co"
SB_KEY="$(python3 - <<'PY'
import base64, json
b = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
print(b({"alg": "HS256", "typ": "JWT"}) + "." +
      b({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "service_role", "iat": 1700000000, "exp": 2000000000}) +
      ".ZmFrZS1zaWduYXR1cmUtZm9yLWRlbW8tb25seS0wMDAwMDA")
PY
)"
FB_DB="https://archaeologist-demo-default-rtdb.firebaseio.com"

mkdir -p assets/env
cat > assets/env/app.env <<ENV
API_BASE_URL=https://api.archaeologist-demo.example
STRIPE_SECRET_KEY=$STRIPE
AWS_ACCESS_KEY_ID=$AWS_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET
DEBUG_ADMIN_PASSWORD=hunter2-demo
ENV
mkdir -p assets/certs assets/config
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=api.archaeologist-demo.example" \
  -keyout /dev/null -out assets/certs/api_pin.pem 2>/dev/null
cat > assets/config/app_config.json <<JSON
{"env": "production",
 "sentry_dsn": "https://0123456789abcdef0123456789abcdef@o12345.ingest.sentry.io/678",
 "admin_panel": "https://admin.archaeologist-demo.example/internal",
 "feature_flags": {"debug_menu": true}}
JSON

python3 - <<'PY'
import re, pathlib
p = pathlib.Path("android/app/src/main/AndroidManifest.xml")
s = p.read_text()
s = s.replace("<application", '<uses-permission android:name="android.permission.INTERNET"/>\n    <application android:usesCleartextTraffic="true" android:allowBackup="true"', 1)
s = s.replace("</application>", '''
        <receiver android:name="com.archaeologist.demo.DebugReceiver" android:exported="true">
            <intent-filter><action android:name="com.archaeologist.demo.DEBUG_RESET"/></intent-filter>
        </receiver>
        <activity android:name="com.archaeologist.demo.DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="archdemo" android:host="pay"/>
            </intent-filter>
        </activity>
    </application>''', 1)
p.write_text(s)
PY

"$FLUTTER" pub get >/dev/null
DEFINES=(--dart-define=SUPABASE_URL="$SB_URL" --dart-define=SUPABASE_KEY="$SB_KEY"
         --dart-define=GOOGLE_KEY="$GOOGLE" --dart-define=FIREBASE_DB="$FB_DB")
TP=(--target-platform android-arm64,android-x64)

"$FLUTTER" build apk --release "${TP[@]}" "${DEFINES[@]}"
cp build/app/outputs/flutter-apk/app-release.apk "$OUT/demo-release.apk"

"$FLUTTER" build apk --release "${TP[@]}" "${DEFINES[@]}" --obfuscate --split-debug-info=build/symbols
cp build/app/outputs/flutter-apk/app-release.apk "$OUT/demo-obfuscated.apk"

"$FLUTTER" build apk --debug --target-platform android-x64 "${DEFINES[@]}"
cp build/app/outputs/flutter-apk/app-debug.apk "$OUT/demo-debug.apk"

"$FLUTTER" build appbundle --release "${TP[@]}" "${DEFINES[@]}"
cp build/app/outputs/bundle/release/app-release.aab "$OUT/demo-release.aab"

ls -la "$OUT"
