from __future__ import annotations

import re
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field

from . import dex as dexmod

CATEGORIES = {
    "root": "Root / jailbreak detection",
    "hooking": "Frida / hooking framework detection",
    "debugger": "Debugger detection",
    "adb": "ADB / USB debugging detection",
    "developer": "Developer options detection",
    "emulator": "Emulator detection",
    "overlay": "Overlay / tapjacking protection",
    "screen": "Screenshot / screen-recording protection",
    "devicelock": "Device lock (passcode) check",
    "mocklocation": "Mock location detection",
    "network": "VPN / proxy detection",
    "integrity": "App integrity / install-source / attestation",
    "accessibility": "Accessibility-service / input-method checks",
    "rasp": "Commercial RASP / app-shielding SDK",
}

BYPASS_HINTS = {
    "root": "Hide root (Magisk DenyList + Shamiko / KernelSU), or hook File.exists, Runtime.exec('su'), "
            "PackageManager lookups and Build.TAGS (frida/anti_detection.js).",
    "hooking": "Rename/relocate frida-server, non-default port (-l 0.0.0.0:1337), use a stealth build "
               "(e.g. hluda/florida) or Frida Gadget; Java-level /proc/self/maps scans are filtered by "
               "anti_detection.js, native ones are not.",
    "debugger": "Hook android.os.Debug.isDebuggerConnected/waitingForDebugger -> false; native "
                "TracerPid/ptrace checks need a native hook.",
    "adb": "Hook Settings.Global/Secure.getInt('adb_enabled') -> 0, or toggle USB debugging off while "
           "using frida over TCP.",
    "developer": "Hook Settings.Global/Secure.getInt('development_settings_enabled') -> 0.",
    "emulator": "Test on a physical device, or spoof android.os.Build fields / ro.* properties "
                "(anti_detection.js) and hide emulator files (/dev/qemu_pipe ...).",
    "overlay": "Defensive control (protects users from tapjacking); affects UI-automation tools, "
               "not traffic interception.",
    "screen": "FLAG_SECURE blocks screenshots/recording; anti_detection.js strips it from Window flags.",
    "devicelock": "Set a screen lock on the test device, or hook KeyguardManager.isDeviceSecure -> true.",
    "mocklocation": "Hook Location.isFromMockProvider/isMock -> false.",
    "network": "Avoid VPN-based interception (use iptables/transparent proxy) or hook "
               "NetworkCapabilities.hasTransport(TRANSPORT_VPN) -> false.",
    "integrity": "Server-side attestation (Play Integrity / SafetyNet / App Check) cannot be bypassed "
                 "client-side reliably; install from Play on a certified device, or test endpoints "
                 "directly. Installer checks: hook getInstallerPackageName -> com.android.vending.",
    "accessibility": "Informational: the app inspects enabled accessibility services / keyboards.",
    "rasp": "Commercial shielding usually combines root/hook/debug/emulator/tamper checks natively; "
            "expect kill-switches. Map which checks fire with frida -l anti_detection.js first.",
}

STRING_INDICATORS: list[tuple[str, str, str, str]] = [
    ("root", r"^/(system|sbin|vendor|data/local|data/local/xbin|data/local/bin|system/sd/xbin|system/bin/failsafe|su/bin|cache|dev)(/xbin|/bin)?/su$", "su binary path", "strong"),
    ("root", r"Superuser\.apk|/system/app/Superuser", "Superuser.apk", "strong"),
    ("root", r"^(com\.topjohnwu\.magisk|io\.github\.huskydg\.magisk|com\.fox2code\.mmm|me\.weishu\.kernelsu|"
             r"eu\.chainfire\.supersu|com\.noshufou\.android\.su|com\.koushikdutta\.superuser|"
             r"com\.thirdparty\.superuser|com\.yellowes\.su|com\.kingroot\.kinguser|com\.kingo\.root|"
             r"com\.smedialink\.oneclickroot|com\.zhiqupk\.root\.global|com\.alephzain\.framaroot|"
             r"com\.devadvance\.rootcloak2?|com\.amphoras\.hidemyroot|com\.formyhm\.hideroot|"
             r"com\.saurik\.substrate|com\.chelpus\.lackypatch|com\.dimonvideo\.luckypatcher|"
             r"com\.ramdroid\.appquarantine)$", "root/root-hiding app package", "strong"),
    ("root", r"^test-keys$", "Build.TAGS test-keys", "weak"),
    ("root", r"(?i)\bmagisk\b|/sbin/\.magisk|/data/adb/magisk|zygisk|kernelsu|/data/adb/ksu", "Magisk/Zygisk/KernelSU artefact", "strong"),
    ("root", r"^(which su|/system/xbin/which su|su -c.*)$", "`which su` / su exec", "strong"),
    ("root", r"^ro\.(debuggable|secure)$", "ro.debuggable / ro.secure property", "weak"),
    ("root", r"^(busybox|/system/xbin/busybox|/system/bin/busybox)$", "busybox", "weak"),
    ("root", r"^/(system|vendor|data)?/?(etc/)?(init\.d|xbin)$|^/system/xbin$", "writable system dirs", "weak"),
    ("root", r"^/Applications/(Cydia|Sileo|Zebra|Installer|blackra1n|FakeCarrier|Icy|IntelliScreen|MxTube|"
             r"RockApp|SBSettings|WinterBoard)\.app", "jailbreak app path", "strong"),
    ("root", r"^/(Library/MobileSubstrate|usr/lib/libsubstitute|usr/lib/substrate|usr/lib/TweakInject|"
             r"var/jb|private/var/jb|var/binpack|private/jailbreak\.txt|etc/apt|private/var/lib/apt|"
             r"private/var/lib/cydia|usr/sbin/sshd|usr/bin/sshd|usr/libexec/sftp-server|bin/bash|bin/sh|"
             r"usr/libexec/cydia|private/var/stash|\.bootstrapped|\.installed_dopamine)", "jailbreak file path", "strong"),
    ("root", r"^(cydia|sileo|zbra|undecimus|filza|activator)://", "jailbreak URL scheme", "strong"),
    ("root", r"IOSSecuritySuite|DTTJailbreakDetection|amIJailbroken|^isJailBroken$|^isJailbroken$|^jailbroken$", "jailbreak check API", "strong"),
    ("hooking", r"(?i)^(frida|frida-server|frida-agent|frida-gadget|frida-helper.*|libfrida.*|re\.frida\.server|"
                r"gum-js-loop|gmain|gdbus|linjector|pool-frida|fridaserver)$", "Frida artefact name", "strong"),
    ("hooking", r"(?i)frida[-_](server|agent|gadget|helper)|libfrida|/data/local/tmp/re\.frida|re\.frida\.|"
                r"gum-js-loop|FridaGadget", "Frida artefact", "strong"),
    ("hooking", r"^(27042|27043)$", "Frida default port", "weak"),
    ("hooking", r"(?i)de\.robv\.android\.xposed|XposedBridge|xposed_?installer|org\.lsposed|io\.va\.exposed|"
                r"org\.meowcat\.edxposed|EdXposed|LSPosed|taichi", "Xposed/LSPosed", "strong"),
    ("hooking", r"(?i)com\.saurik\.substrate|MobileSubstrate|libsubstrate|cynject|libhooker|SubstrateLoader|"
                r"SSLKillSwitch|substitute-loader", "Substrate/libhooker", "strong"),
    ("hooking", r"^/proc/self/(maps|task|fd)$|^/proc/%d/maps$|^/proc/\d+/maps$", "/proc/self/maps scan", "weak"),
    ("hooking", r"(?i)\bobjection\b|cycript|\bshadow\.dylib|libcycript|DYLD_INSERT_LIBRARIES", "objection/cycript/dyld injection", "strong"),
    ("debugger", r"^TracerPid:?\s*$|TracerPid", "TracerPid (/proc/self/status)", "strong"),
    ("debugger", r"^/proc/self/status$", "/proc/self/status", "weak"),
    ("debugger", r"(?i)^(isDebuggerConnected|isDebuggerAttached|debuggerAttached|amIDebugged|isBeingDebugged|"
                 r"checkDebugger|antiDebug)$", "debugger check name", "strong"),
    ("adb", r"^(adb_enabled|ADB_ENABLED|adb_wifi_enabled|init\.svc\.adbd|service\.adb\.tcp\.port|"
            r"persist\.sys\.usb\.config|sys\.usb\.(state|config))$", "ADB setting/property", "strong"),
    ("adb", r"(?i)^(isAdbEnabled|usbDebugging(Check|Enabled)?|isUsbDebugging.*)$", "ADB check name", "strong"),
    ("developer", r"^(development_settings_enabled|DEVELOPMENT_SETTINGS_ENABLED)$", "developer options setting", "strong"),
    ("developer", r"(?i)^(developerMode|isDevelopmentModeEnable|isDeveloperMode(Enabled)?|devMode(Enabled)?)$", "developer-mode check name", "strong"),
    ("emulator", r"^(goldfish|ranchu|vbox86|vbox86p|ttVM_x86|nox|andy|droid4x|genymotion|Genymotion)$", "emulator hardware/board name", "strong"),
    ("emulator", r"(?i)^(generic_x86(_64)?|sdk_gphone.*|google_sdk|sdk_google.*|emulator64.*|Android SDK built for x86.*|"
                 r"vsoc_x86.*|gce_x86|aosp_cf_x86.*)$", "emulator product/model", "strong"),
    ("emulator", r"^(/dev/qemu_pipe|/dev/socket/qemud|/dev/socket/genyd|/dev/socket/baseband_genyd|"
                 r"/system/lib/libc_malloc_debug_qemu\.so|/sys/qemu_trace|/system/bin/qemu-props|"
                 r"/dev/vboxguest|/dev/vboxuser|/system/bin/nox-prop|/system/bin/ttVM-prop|"
                 r"/system/bin/microvirtd|/data/.bluestacks\.prop|fstab\.andy|ueventd\.andy\.rc)$", "emulator device file", "strong"),
    ("emulator", r"^(ro\.kernel\.qemu|ro\.kernel\.qemu\.gles|init\.svc\.qemud|init\.svc\.qemu-props|"
                 r"qemu\.hw\.mainkeys|ro\.bootloader|ro\.hardware|ro\.product\.model|ro\.boot\.qemu)$", "emulator system property", "weak"),
    ("emulator", r"^com\.(bluestacks|bignox|vphone|microvirt|mumu|ldmnq|genymotion|kaopu)(\.[\w.]+)?$|"
                 r"\b(BlueStacks|MEmu|LDPlayer|NoxPlayer|Genymotion)\b", "emulator vendor package/name", "strong"),
    ("emulator", r"^(15555215554|000000000000000|310260000000000|e21833235b6eef10)$", "emulator default IMEI/IMSI", "strong"),
    ("emulator", r"(?i)^(isEmulator|isRealDevice|isPhysicalDevice|checkEmulator|isSimulator)$", "emulator check name", "strong"),
    ("overlay", r"(?i)^(filterTouchesWhenObscured|FLAG_WINDOW_IS_(PARTIALLY_)?OBSCURED|hideOverlayWindows|"
                r"android\.permission\.HIDE_OVERLAY_WINDOWS)$", "overlay/tapjacking protection", "strong"),
    ("screen", r"^(FLAG_SECURE|UIScreenCapturedDidChangeNotification|UIApplicationUserDidTakeScreenshotNotification|"
               r"isCaptured|android\.permission\.DETECT_SCREEN_CAPTURE)$", "screen capture control", "strong"),
    ("mocklocation", r"^(mock_location|isFromMockProvider|isMock|allow_mock_location)$", "mock location", "strong"),
    ("mocklocation", r"(?i)^(com\.lexa\.fakegps|com\.incorporateapps\.fakegps\.fre|com\.fakegps\.mock|"
                     r"com\.blogspot\.newapphorizons\.fakegps)$", "fake-GPS app package", "strong"),
    ("network", r"^(tun0|ppp0|tap0|utun\d*|ipsec\d*)$", "VPN interface name", "weak"),
    ("network", r"^(http\.proxyHost|https\.proxyHost|http\.proxyPort|kCFNetworkProxiesHTTPProxy|"
                r"kCFProxyHostNameKey)$", "proxy setting lookup", "weak"),
    ("integrity", r"^(com\.android\.vending)$", "Play Store installer id", "weak"),
    ("integrity", r"com\.google\.android\.play\.core\.integrity|IntegrityTokenRequest|StandardIntegrityManager|"
                  r"com\.google\.android\.gms\.safetynet|SafetyNetApi|^attest(ation)?Token$", "Play Integrity / SafetyNet", "strong"),
    ("accessibility", r"^(enabled_accessibility_services|default_input_method|accessibility_enabled)$", "accessibility/IME setting", "weak"),
]

API_INDICATORS: list[tuple[str, str, str, str, str]] = [
    ("debugger", "Landroid/os/Debug;", "isDebuggerConnected", "Debug.isDebuggerConnected()", "strong"),
    ("debugger", "Landroid/os/Debug;", "waitingForDebugger", "Debug.waitingForDebugger()", "strong"),
    ("overlay", "Landroid/view/View;", "setFilterTouchesWhenObscured", "View.setFilterTouchesWhenObscured()", "strong"),
    ("overlay", "Landroid/view/Window;", "setHideOverlayWindows", "Window.setHideOverlayWindows()", "strong"),
    ("overlay", "Landroid/provider/Settings;", "canDrawOverlays", "Settings.canDrawOverlays()", "weak"),
    ("screen", "Landroid/app/Activity;", "registerScreenCaptureCallback", "Activity.registerScreenCaptureCallback()", "strong"),
    ("devicelock", "Landroid/app/KeyguardManager;", "isKeyguardSecure", "KeyguardManager.isKeyguardSecure()", "strong"),
    ("devicelock", "Landroid/app/KeyguardManager;", "isDeviceSecure", "KeyguardManager.isDeviceSecure()", "strong"),
    ("mocklocation", "Landroid/location/Location;", "isFromMockProvider", "Location.isFromMockProvider()", "strong"),
    ("mocklocation", "Landroid/location/Location;", "isMock", "Location.isMock()", "strong"),
    ("integrity", "Landroid/content/pm/PackageManager;", "getInstallerPackageName", "PackageManager.getInstallerPackageName()", "strong"),
    ("integrity", "Landroid/content/pm/PackageManager;", "getInstallSourceInfo", "PackageManager.getInstallSourceInfo()", "strong"),
    ("network", "Landroid/net/VpnService;", "prepare", "VpnService.prepare()", "weak"),
    ("accessibility", "Landroid/view/accessibility/AccessibilityManager;", "getEnabledAccessibilityServiceList",
     "AccessibilityManager.getEnabledAccessibilityServiceList()", "weak"),
    ("accessibility", "Landroid/view/inputmethod/InputMethodManager;", "getEnabledInputMethodList",
     "InputMethodManager.getEnabledInputMethodList()", "weak"),
]

CLASS_INDICATORS: list[tuple[str, str, str]] = [
    ("root", "Lcom/scottyab/rootbeer/", "RootBeer"),
    ("root", "Lcom/kimchangyoun/rootbeerFresh/", "RootBeerFresh"),
    ("root", "Lappmire/be/flutterjailbreakdetection/", "flutter_jailbreak_detection (Android side)"),
    ("rasp", "Lcom/aheaditec/talsec/", "Talsec / freeRASP"),
    ("rasp", "Lcom/threatmark/", "ThreatMark (device risk / behavioural fraud SDK)"),
    ("rasp", "Lio/codevo/", "Codevo Octopus (RASP / mobile security SDK)"),
    ("rasp", "Lcom/phaymobile/mastercard/mcbp/", "Mastercard MCBP (HCE payment SDK with device checks)"),
    ("rasp", "Lcom/aheaditec/talsec_security/", "Talsec / freeRASP"),
    ("rasp", "Lno/promon/", "Promon SHIELD"),
    ("rasp", "Lcom/guardsquare/dexguard/", "Guardsquare DexGuard runtime"),
    ("rasp", "Lio/approov/", "Approov"),
    ("rasp", "Lcom/criticalblue/approovsdk/", "Approov"),
    ("rasp", "Lcom/zimperium/", "Zimperium"),
    ("rasp", "Lcom/inka/appsealing/", "AppSealing"),
    ("rasp", "Lcom/lockincomp/liapp", "LIAPP"),
    ("rasp", "Lcom/verimatrix/", "Verimatrix"),
    ("rasp", "Lcom/appdome/", "Appdome"),
    ("rasp", "Lcom/arxan/", "Digital.ai / Arxan"),
    ("rasp", "Lcom/secneo/", "SecNeo/Bangcle"),
    ("rasp", "Lcom/qihoo/util/", "Qihoo Jiagu"),
    ("rasp", "Lcom/tencent/StubShell/", "Tencent Legu"),
    ("integrity", "Lcom/google/android/play/core/integrity/", "Play Integrity API"),
    ("integrity", "Lcom/google/android/gms/safetynet/", "SafetyNet Attestation"),
    ("integrity", "Lcom/google/firebase/appcheck/", "Firebase App Check"),
    ("integrity", "Lcom/pairip/", "Google Play automatic integrity protection (PairIP)"),
]

PACKAGE_INDICATORS: dict[str, tuple[str, str]] = {
    "freerasp": ("rasp", "Talsec freeRASP (root, hook, debugger, emulator, tamper, device binding)"),
    "flutter_jailbreak_detection": ("root", "root/jailbreak + developer mode check"),
    "safe_device": ("root", "root/jailbreak, emulator, mock location, USB debugging, dev mode"),
    "jailbreak_root_detection": ("root", "root/jailbreak, Frida, emulator, debugger, dev mode"),
    "root_checker_plus": ("root", "root check"),
    "trust_device_info": ("root", "root/emulator checks"),
    "flutter_root_jailbreak_checker": ("root", "root/jailbreak checks"),
    "detect_fake_location": ("mocklocation", "mock location detection"),
    "trust_location": ("mocklocation", "mock location detection"),
    "flutter_windowmanager": ("screen", "Window flags (usually FLAG_SECURE)"),
    "flutter_windowmanager_plus": ("screen", "Window flags (usually FLAG_SECURE)"),
    "screen_protector": ("screen", "screenshot / recording protection"),
    "no_screenshot": ("screen", "screenshot protection"),
    "secure_application": ("screen", "hides content in app switcher"),
    "flutter_prevent_screen_capture": ("screen", "screen capture protection"),
    "firebase_app_check": ("integrity", "Firebase App Check (Play Integrity / DeviceCheck attestation)"),
    "app_attest_integrity": ("integrity", "App Attest / Play Integrity"),
    "play_integrity_flutter": ("integrity", "Play Integrity"),
    "approov_service_flutter_httpclient": ("rasp", "Approov API attestation"),
    "approov_service_flutter_dio": ("rasp", "Approov API attestation"),
    "device_info_plus": ("emulator", "exposes isPhysicalDevice (often used for emulator checks)"),
    "local_auth": ("devicelock", "biometric / device credential check"),
    "vpn_check": ("network", "VPN detection"),
    "check_vpn_connection": ("network", "VPN detection"),
    "is_lock_screen": ("devicelock", "device lock check"),
}

NATIVE_LIB_INDICATORS: dict[str, tuple[str, str]] = {
    "libtalsec": ("rasp", "Talsec"), "libsecurity": ("rasp", "Talsec / generic security lib"),
    "libshield": ("rasp", "Promon SHIELD"), "libapproov": ("rasp", "Approov"), "libdexguard": ("rasp", "DexGuard"),
    "libappdome": ("rasp", "Appdome"), "libliapp": ("rasp", "LIAPP"), "libcovault": ("rasp", "AppSealing"),
    "libjiagu": ("rasp", "Qihoo Jiagu"), "libsecexe": ("rasp", "Bangcle"), "libsecmain": ("rasp", "Bangcle"),
    "libDexHelper": ("rasp", "SecNeo"), "libtup": ("rasp", "Tencent"), "libshella": ("rasp", "Tencent Legu"),
    "libzdefend": ("rasp", "Zimperium"), "libtoolChecker": ("root", "RootBeer native"),
}

TELEMETRY_PREFIXES = {
    "com.google.firebase.crashlytics": "Firebase Crashlytics", "com.crashlytics": "Crashlytics",
    "com.google.android.gms": "Google Play services", "com.google.firebase": "Firebase",
    "com.google.android.play.core.integrity": None,
    "io.sentry": "Sentry", "com.appsflyer": "AppsFlyer", "com.adjust.sdk": "Adjust",
    "com.datadog": "Datadog", "com.newrelic": "New Relic", "com.bugsnag": "Bugsnag",
    "com.instabug": "Instabug", "com.microsoft.appcenter": "App Center", "com.amplitude": "Amplitude",
    "com.mixpanel": "Mixpanel", "com.onesignal": "OneSignal", "io.embrace": "Embrace",
    "com.facebook": "Facebook SDK", "com.stripe": "Stripe (fraud signals)",
    "com.dynatrace": "Dynatrace", "com.appdynamics": "AppDynamics", "io.branch": "Branch",
    "com.braze": "Braze", "com.clevertap": "CleverTap", "com.segment": "Segment",
    "com.huawei.hms": "Huawei HMS", "com.kochava": "Kochava", "com.singular": "Singular",
    "com.uxcam": "UXCam", "com.commencis.appconnect": "Commencis AppConnect (analytics)", "com.smartlook": "Smartlook", "io.invertase": "FlutterFire",
    "com.google.android.datatransport": "Google datatransport", "androidx": "AndroidX",
    "com.android": "Android library", "kotlin": "Kotlin stdlib", "okhttp3": "OkHttp",
    "io.flutter.embedding": "Flutter embedding", "com.scottyab.rootbeer": None,
    "com.google.android.material": "Material Components", "com.google.android.libraries": "Google library", "com.google.android.exoplayer2": "ExoPlayer",
    "androidx.media3": "Media3", "dev.fluttercommunity.plus": "Flutter Community plugin",
}
SDK_MARKERS = {
    "FirebaseCrashlytics": "Firebase Crashlytics", "Crashlytics": "Crashlytics", "io.sentry": "Sentry",
    "sentry-": "Sentry", "AppsFlyer": "AppsFlyer", "appsflyer": "AppsFlyer", "Adjust": "Adjust",
    "datadog": "Datadog", "newrelic": "New Relic", "NewRelic": "New Relic", "bugsnag": "Bugsnag",
    "Bugsnag": "Bugsnag", "instabug": "Instabug", "Instabug": "Instabug", "appcenter": "App Center",
    "amplitude": "Amplitude", "mixpanel": "Mixpanel", "OneSignal": "OneSignal", "embrace": "Embrace",
    "FirebaseInstallations": "Firebase", "FA-SVC": "Firebase Analytics", "GoogleCertificates": "Google Play services",
    "com.google.android.gms": "Google Play services", "dynatrace": "Dynatrace", "Dynatrace": "Dynatrace",
    "m.stripe.com": "Stripe (fraud signals)", "stripe_": "Stripe (fraud signals)",
    "com/stripe/": "Stripe (fraud signals)", "com.stripe.": "Stripe (fraud signals)",
    "isPhysicalDevice": "device_info_plus (reports isPhysicalDevice)",
    "is_mocked": "geolocator (reports isMocked)", "isMocked": "geolocator (reports isMocked)",
    "installerStore": "package_info_plus (reports installer)",
}
_MARKER_RX = re.compile("|".join(re.escape(k) for k in sorted(SDK_MARKERS, key=len, reverse=True)))


@dataclass
class Evidence:
    category: str
    label: str
    strength: str
    source: str
    where: str
    value: str
    owner: str | None = None

    def key(self):
        return (self.category, self.label, self.where, self.value)


@dataclass
class CategoryResult:
    category: str
    title: str
    verdict: str
    evidence: list[dict] = field(default_factory=list)
    hint: str = ""


def _compile_strings():
    parts = []
    for i, (_cat, rx, _label, _st) in enumerate(STRING_INDICATORS):
        if rx.startswith("(?i)"):
            rx = "(?i:" + rx[4:] + ")"
        parts.append(f"(?P<i{i}>{rx})")
    return re.compile("|".join(parts))


_STR_RX = _compile_strings()


PREFILTER = tuple("""su magisk zygisk kernelsu keys debuggable secure busybox xbin init.d applications substrate
library jb usr/ bin/ etc/ apt cydia private bootstrap dopamine sileo zbra undecimus filza activator security
jailb frida gum- gmain gdbus linjector 2704 xposed lsposed exposed taichi cynject sslkill substitute hooker
proc/ objection cycript shadow dyld tracer debug adb usb development developer devmode goldfish ranchu vbox
ttvm nox andy droid4x genymotion generic sdk emulator vsoc gce_ aosp qemu geny microvirt bluestacks fstab
ueventd kernel hardware bootloader mainkeys product bignox vphone mumu ldmnq kaopu memu ldplayer 1555
000000000000000 3102600 e21833 physical realdevice simulator obscured overlay flag_secure captured screenshot
screen_capture mock fakegps tun0 ppp0 tap0 utun ipsec proxy vending integrity safetynet attest accessibility
input_method fox2code king root patch quarantine binpack""".split())


def _match_string(s: str) -> tuple[str, str, str] | None:
    if len(s) > 300:
        return None
    low = s.lower()
    if not any(k in low for k in PREFILTER):
        return None
    m = _STR_RX.search(s)
    if not m:
        return None
    i = int(m.lastgroup[1:])
    cat, _rx, label, st = STRING_INDICATORS[i]
    return cat, label, st


def _owner_from_class(cls: str) -> str | None:
    best = None
    for pre, name in TELEMETRY_PREFIXES.items():
        if cls == pre or cls.startswith(pre + "."):
            if best is None or len(pre) > len(best[0]):
                best = (pre, name)
    return best[1] if best else None


DEX_SKIP_LABELS = {"jailbreak check API", "emulator check name", "developer-mode check name"}


def scan_dex(data: bytes, name: str) -> list[Evidence]:
    try:
        d = dexmod.Dex(data)
        strings = d.strings
    except (ValueError, IndexError, Exception):
        return []
    out: list[Evidence] = []
    hits: dict[int, tuple[str, str, str]] = {}
    marker_idx: dict[int, str] = {}
    for i, s in enumerate(strings):
        m = _match_string(s)
        if m and m[1] not in DEX_SKIP_LABELS:
            hits[i] = m
        if len(s) < 200 and not (s.startswith(("L", "[")) and s.endswith(";")):
            mm = _MARKER_RX.search(s)
            if mm:
                marker_idx[i] = SDK_MARKERS[mm.group()]
    type_names = set()
    for t in range(d.n_type):
        type_names.add(d.type_name(t))
    for cat, prefix, label in CLASS_INDICATORS:
        hit = sorted(t for t in type_names if t.startswith(prefix))
        if hit:
            out.append(Evidence(cat, label, "strong", "dex-class", f"{name}: {dexmod.dotted(hit[0])}",
                                f"{len(hit)} class(es)"))
    mindex = d.method_index()
    want_m: dict[int, tuple] = {}
    for spec in API_INDICATORS:
        for idx in mindex.get((spec[1], spec[2]), []):
            want_m[idx] = spec
    refs_s = d.string_refs(set(hits)) if hits else []
    refs_m = d.invoke_refs(set(want_m)) if want_m else []
    cls_marker: dict[str, str] = {}
    if marker_idx:
        for si, mi in d.string_refs(set(marker_idx)):
            cls_marker.setdefault(d.method(mi)[0], marker_idx[si])

    def owner(cls_desc: str) -> str | None:
        dotted = dexmod.dotted(cls_desc)
        o = _owner_from_class(dotted)
        if o is None and dotted.startswith(("com.scottyab", "com.google.android.play.core.integrity")):
            return None
        if o:
            return o
        if cls_desc in cls_marker:
            return cls_marker[cls_desc]
        outer = cls_desc.split("$", 1)[0] + (";" if "$" in cls_desc else "")
        return cls_marker.get(outer)

    for si, mi in refs_s:
        cat, label, st = hits[si]
        cls, meth = d.method(mi)
        out.append(Evidence(cat, label, st, "dex", f"{dexmod.dotted(cls)}.{meth}", strings[si], owner(cls)))
    for idx, mi in refs_m:
        cat, _c, _m, label, st = want_m[idx]
        cls, meth = d.method(mi)
        out.append(Evidence(cat, label, st, "dex", f"{dexmod.dotted(cls)}.{meth}", label, owner(cls)))
    return out


_NATIVE_BYTES_RX = re.compile(rb"[\x20-\x7e]{4,300}")


def scan_native(data: bytes, name: str) -> list[Evidence]:
    out = []
    seen = set()
    for m in _NATIVE_BYTES_RX.finditer(data):
        s = m.group().decode("latin-1")
        r = _match_string(s)
        if r and s not in seen:
            seen.add(s)
            out.append(Evidence(r[0], r[1], r[2], "native", name, s))
    return out


def scan_dart(strings: list[str], packages: set[str] = frozenset()) -> list[Evidence]:
    out = []
    for s in strings:
        r = _match_string(s)
        if r:
            owner = None
            if s == "isPhysicalDevice" and "device_info_plus" in packages:
                owner = "device_info_plus (reports isPhysicalDevice)"
            out.append(Evidence(r[0], r[1], r[2], "dart", "Dart snapshot", s, owner))
    return out


def analyze(bundle, dart_strings: list[str], packages: set[str], native_libs: list[str],
            android: dict | None) -> list[dict]:
    ev: list[Evidence] = []
    for p in sorted(packages):
        if p in PACKAGE_INDICATORS:
            cat, label = PACKAGE_INDICATORS[p]
            st = "weak" if p in ("device_info_plus", "local_auth") else "strong"
            ev.append(Evidence(cat, label, st, "package", f"package:{p}", p))
    for lib in native_libs:
        low = lib.lower()
        for needle, (cat, label) in NATIVE_LIB_INDICATORS.items():
            if low.startswith(needle.lower()):
                ev.append(Evidence(cat, label, "strong", "native-lib", lib, lib))
    a = android or {}
    for perm in a.get("permissions", []):
        if perm in ("android.permission.HIDE_OVERLAY_WINDOWS",):
            ev.append(Evidence("overlay", "HIDE_OVERLAY_WINDOWS permission", "strong", "manifest",
                               "AndroidManifest.xml", perm))
        if perm in ("android.permission.DETECT_SCREEN_CAPTURE",):
            ev.append(Evidence("screen", "DETECT_SCREEN_CAPTURE permission", "strong", "manifest",
                               "AndroidManifest.xml", perm))
    for q in a.get("queries", []):
        r = _match_string(q)
        if r:
            ev.append(Evidence(r[0], r[1] + " (manifest <queries>)", "strong", "manifest",
                               "AndroidManifest.xml <queries>", q))
    ev += scan_dart(dart_strings, packages)
    for path, e in sorted(bundle.entries.items()):
        if re.fullmatch(r"classes\d*\.dex", path) and e.size < 120 * 1024 * 1024:
            ev += scan_dex(e.read(), path)
        elif re.fullmatch(r"lib/[^/]+/[^/]+\.so", path):
            so = path.rsplit("/", 1)[1]
            if so in ("libflutter.so", "libapp.so") or e.size > 80 * 1024 * 1024:
                continue
            abi = path.split("/")[1]
            if abi not in ("arm64-v8a", "x86_64", "armeabi-v7a", "x86"):
                continue
            ev += scan_native(e.read(), so)
        elif bundle.platform == "ios" and (re.fullmatch(r"[^/]+", path) or
                                           re.fullmatch(r"Frameworks/([^/]+)\.framework/\1", path)):
            if path in ("Frameworks/App.framework/App", "Frameworks/Flutter.framework/Flutter"):
                continue
            head = e.read()
            if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                ev += scan_native(head, path)
    uniq: dict[tuple, Evidence] = {}
    for x in ev:
        k = (x.category, x.label, x.value, x.where if x.source != "native" else x.where.split("/")[-1], x.owner)
        uniq.setdefault(k, x)
    return _summarise(list(uniq.values()))


def _summarise(ev: list[Evidence]) -> list[dict]:
    by: dict[str, list[Evidence]] = defaultdict(list)
    for x in ev:
        by[x.category].append(x)
    results = []
    for cat in CATEGORIES:
        items = by.get(cat)
        if not items:
            continue
        enforce = [x for x in items if not x.owner]
        strong = [x for x in enforce if x.strength == "strong"]
        if strong:
            verdict = "enforcement-candidate"
        elif enforce:
            verdict = "weak-signal"
        else:
            verdict = "telemetry-only"
        items.sort(key=lambda x: (x.owner is not None, x.strength != "strong", x.source, x.where))
        results.append({
            "category": cat, "title": CATEGORIES[cat], "verdict": verdict, "hint": BYPASS_HINTS.get(cat, ""),
            "evidence": [{"label": x.label, "strength": x.strength, "source": x.source, "where": x.where,
                          "value": x.value, "owner": x.owner} for x in items],
        })
    return results
