from __future__ import annotations

PINNING, RASP, NETWORK, STORAGE, BACKEND, AUTH, CRYPTO, WEBVIEW, STATE, PAYMENT, ANALYTICS, OTHER = (
    "pinning", "rasp", "network", "storage", "backend", "auth", "crypto", "webview",
    "state", "payment", "analytics", "other")

PACKAGES: dict[str, tuple[str, str]] = {
    "http_certificate_pinning": (PINNING, "Certificate pinning via native plugin. Hook the plugin's "
                                 "check() channel call or the Dart-side result in addition to BoringSSL."),
    "ssl_pinning_plugin": (PINNING, "Certificate pinning via native plugin: the check runs on the "
                           "platform side, hook the plugin's native implementation or its MethodChannel result."),
    "dio_certificate_pinning": (PINNING, "Pinning implemented as a Dio interceptor."),
    "certificate_pinning_httpclient": (PINNING, "Pinning via a custom HttpClient SecurityContext."),
    "approov_service_flutter_httpclient": (RASP, "Approov API attestation. TLS bypass alone is NOT enough: "
                                           "the backend rejects requests without a valid Approov token."),
    "approov_service_flutter_dio": (RASP, "Approov API attestation (Dio). See above."),
    "freerasp": (RASP, "Talsec freeRASP: root/jailbreak/hook/debugger/repackaging detection. Expect the app "
                 "to react (kill or report) when Frida is attached."),
    "flutter_jailbreak_detection": (RASP, "Root/jailbreak check (RootBeer / IOSSecuritySuite). Hook "
                                    "the plugin's MethodChannel results or the native checks."),
    "safe_device": (RASP, "Root/jailbreak/emulator/mock-location checks over a MethodChannel."),
    "jailbreak_root_detection": (RASP, "Root/jailbreak/emulator/Frida checks over a MethodChannel."),
    "root_checker_plus": (RASP, "Root detection plugin."),
    "flutter_windowmanager": (RASP, "Usually sets FLAG_SECURE (screenshot blocking)."),
    "screen_protector": (RASP, "Screenshot / screen-recording protection."),
    "no_screenshot": (RASP, "Screenshot protection."),
    "local_auth": (AUTH, "Biometric gate. Check whether the result only toggles UI (bypassable by hooking "
                   "the channel) or unlocks a Keystore/Keychain-bound secret."),
    "dio": (NETWORK, "Look for interceptors (auth headers, signing, refresh logic) and baseUrl constants."),
    "http": (NETWORK, ""),
    "chopper": (NETWORK, ""),
    "retrofit": (NETWORK, "Generated API client: endpoint paths are usually present as string constants."),
    "graphql_flutter": (NETWORK, "GraphQL client: look for operation documents in strings, test introspection."),
    "graphql": (NETWORK, "GraphQL client: look for operation documents in strings, test introspection."),
    "ferry": (NETWORK, "GraphQL client."),
    "grpc": (NETWORK, "gRPC over HTTP/2: intercept with an h2-capable proxy; .proto names in strings."),
    "web_socket_channel": (NETWORK, "WebSocket traffic: test auth on the socket, not only on HTTP."),
    "socket_io_client": (NETWORK, "Socket.IO traffic."),
    "cronet_http": (NETWORK, "Uses Android Cronet instead of dart:io: BoringSSL-in-libflutter hooks do NOT "
                    "cover it; use Java/OkHttp-style bypasses on Cronet."),
    "cupertino_http": (NETWORK, "Uses NSURLSession instead of dart:io on iOS: needs iOS-native TLS bypass."),
    "native_dio_adapter": (NETWORK, "Routes Dio through Cronet/NSURLSession: native TLS bypass needed."),
    "shared_preferences": (STORAGE, "Plain-text XML/plist storage. Check what is stored after login "
                           "(tokens, PII)."),
    "flutter_secure_storage": (STORAGE, "Keystore/Keychain-backed. Check for fallbacks and iOS accessibility "
                               "options (e.g. first_unlock)."),
    "hive": (STORAGE, "Local box files in app data dir; may be unencrypted unless HiveAesCipher is used."),
    "hive_flutter": (STORAGE, ""),
    "isar": (STORAGE, "Local database file in app data dir."),
    "sqflite": (STORAGE, "SQLite database in app data dir."),
    "sqflite_sqlcipher": (STORAGE, "Encrypted SQLite: look for the passphrase source."),
    "drift": (STORAGE, "SQLite (drift)."),
    "objectbox": (STORAGE, ""),
    "get_storage": (STORAGE, "Plain JSON file storage."),
    "firebase_core": (BACKEND, "Firebase project: verify Firestore/RTDB/Storage rules with the bundled config."),
    "cloud_firestore": (BACKEND, "Firestore: test rules unauthenticated and with a self-registered user."),
    "firebase_database": (BACKEND, "Realtime Database: try GET https://<db>/.json unauthenticated."),
    "firebase_storage": (BACKEND, "Cloud Storage bucket: test list/read/write rules."),
    "firebase_auth": (AUTH, "Check whether open sign-up is enabled even if the app hides it "
                      "(identitytoolkit accounts:signUp with the API key)."),
    "cloud_functions": (BACKEND, "Callable functions: enumerate names from strings, test auth checks."),
    "firebase_remote_config": (BACKEND, "Remote config may expose feature flags / endpoints."),
    "firebase_messaging": (BACKEND, ""),
    "supabase_flutter": (BACKEND, "Supabase: the anon key + URL let you query PostgREST directly. "
                         "Security = RLS policies; test every table."),
    "supabase": (BACKEND, "Supabase: test RLS with the bundled anon key."),
    "appwrite": (BACKEND, "Appwrite backend: check collection permissions."),
    "parse_server_sdk_flutter": (BACKEND, "Parse server: check class-level permissions."),
    "amplify_flutter": (BACKEND, "AWS Amplify: look for amplifyconfiguration (Cognito pool IDs)."),
    "amplify_auth_cognito": (AUTH, "Cognito: check unauthenticated identity pool roles and open sign-up."),
    "google_sign_in": (AUTH, ""),
    "sign_in_with_apple": (AUTH, ""),
    "flutter_facebook_auth": (AUTH, ""),
    "flutter_appauth": (AUTH, "OAuth/OIDC with PKCE: check redirect URI scheme hijacking (custom scheme)."),
    "oauth2": (AUTH, "OAuth client: look for client secrets in strings."),
    "jwt_decoder": (AUTH, "Client decodes JWTs: check whether authorization decisions are made client-side."),
    "dart_jsonwebtoken": (AUTH, "JWT signing/verifying in the client: look for HMAC secrets in strings."),
    "encrypt": (CRYPTO, "Client-side AES/RSA: keys/IVs are frequently hard-coded string constants."),
    "pointycastle": (CRYPTO, "Low-level crypto: look for hard-coded keys and ECB/static IV usage."),
    "crypto": (CRYPTO, "Hashing/HMAC: look for request-signing secrets."),
    "cryptography": (CRYPTO, ""),
    "steel_crypt": (CRYPTO, ""),
    "webview_flutter": (WEBVIEW, "Check JavaScript channels (addJavaScriptChannel) and which URLs load."),
    "flutter_inappwebview": (WEBVIEW, "Check JavaScript handlers (addJavaScriptHandler), file access and "
                             "URL allow-lists; deep links feeding URLs into the webview are a classic bug."),
    "flutter_webview_plugin": (WEBVIEW, "Deprecated webview plugin."),
    "url_launcher": (OTHER, ""),
    "uni_links": (OTHER, "Deep links: test every handled path with untrusted parameters."),
    "app_links": (OTHER, "Deep links / App Links: test every handled path with untrusted parameters."),
    "flutter_riverpod": (STATE, "Riverpod: providers in *.g.dart often reveal repository/API structure."),
    "riverpod": (STATE, ""),
    "hooks_riverpod": (STATE, ""),
    "flutter_bloc": (STATE, "BLoC: event/state class names map user flows."),
    "bloc": (STATE, ""),
    "provider": (STATE, ""),
    "get": (STATE, "GetX: routes are often declared as string constants (GetPage name: '/...')."),
    "mobx": (STATE, ""),
    "go_router": (STATE, "Route paths are string constants: hidden/admin routes and deep-linkable paths."),
    "auto_route": (STATE, "Route paths are string constants."),
    "flutter_stripe": (PAYMENT, "Look for client-side amount handling; secret keys must not be present."),
    "pay": (PAYMENT, ""),
    "in_app_purchase": (PAYMENT, "Check server-side receipt validation (client-only validation = bypass)."),
    "purchases_flutter": (PAYMENT, "RevenueCat: entitlement checks should be server-side."),
    "sentry_flutter": (ANALYTICS, ""),
    "firebase_crashlytics": (ANALYTICS, ""),
    "firebase_analytics": (ANALYTICS, ""),
    "dynatrace_flutter_plugin": (ANALYTICS, ""),
    "flutter_dotenv": (OTHER, "Loads a .env file from flutter_assets: it is shipped in the APK/IPA."),
    "envied": (OTHER, "Compile-time env values: obfuscate:true only XORs them; values are recoverable "
               "from the snapshot."),
}

CATEGORY_LABELS = {
    PINNING: "Certificate pinning", RASP: "RASP / anti-tamper", NETWORK: "Networking",
    STORAGE: "Local storage", BACKEND: "Backend SDKs", AUTH: "Authentication", CRYPTO: "Crypto",
    WEBVIEW: "WebViews", STATE: "Routing / state", PAYMENT: "Payments", ANALYTICS: "Analytics",
    OTHER: "Other",
}

NATIVE_STACK_PACKAGES = {
    "cronet_http", "cupertino_http", "native_dio_adapter", "cloud_firestore", "firebase_database",
    "firebase_storage", "firebase_auth", "firebase_remote_config", "cloud_functions", "firebase_messaging",
    "firebase_analytics", "firebase_crashlytics", "firebase_app_check", "google_sign_in",
    "webview_flutter", "flutter_inappwebview", "amplify_flutter", "purchases_flutter", "flutter_stripe",
}

FRAMEWORK_PACKAGES = {
    "flutter", "flutter_test", "flutter_localizations", "flutter_web_plugins", "sky_engine", "vector_math",
    "collection", "meta", "characters", "material_color_utilities", "async", "path", "intl", "typed_data",
    "stack_trace", "source_span", "string_scanner", "term_glyph", "matcher", "clock", "fake_async",
    "boolean_selector", "leak_tracker", "vm_service", "plugin_platform_interface", "web", "ffi", "jni",
    "http_parser", "csslib", "html", "xml", "petitparser", "uuid", "crypto", "convert", "args", "logging",
    "rxdart", "equatable", "json_annotation", "freezed_annotation", "protobuf", "file", "platform",
    "process", "dlibphonenumber", "cupertino_icons", "lints", "flutter_lints", "win32", "ffigen",
} | set(PACKAGES)

NATIVE_HARDENING = {
    "approov": "Approov (API attestation)",
    "talsec": "Talsec / freeRASP",
    "freerasp": "Talsec / freeRASP",
    "promon": "Promon SHIELD",
    "appdome": "Appdome",
    "dexguard": "Guardsquare DexGuard",
    "ixguard": "Guardsquare iXGuard",
    "arxan": "Digital.ai (Arxan)",
    "zimperium": "Zimperium zDefend",
    "liapp": "LIAPP",
    "jiagu": "Qihoo Jiagu packer",
    "secneo": "SecNeo/Bangcle packer",
    "bangcle": "Bangcle packer",
    "dynatrace": "Dynatrace (monitoring)",
}
