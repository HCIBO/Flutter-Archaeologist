from __future__ import annotations

import json

COMPAT = r"""
function findExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
  return Module.findExportByName(null, name);
}
function findModule(name) {
  try { return Process.findModuleByName(name); } catch (e) {}
  return Process.enumerateModules().find(m => m.name === name || m.path.endsWith('/' + name)) || null;
}
"""

METHOD_CHANNELS = r"""
const APP_CHANNELS = __APP_CHANNELS__;
const ONLY_APP_CHANNELS = false;
const MAX_BYTES = 4096;
const OVERRIDES = {
};

function install() {
  const JNI = Java.use('io.flutter.embedding.engine.FlutterJNI');
  const ByteBuffer = Java.use('java.nio.ByteBuffer');
  const Buffer = Java.use('java.nio.Buffer');
  const pending = {};

  function show(ch) {
    if (!ONLY_APP_CHANNELS) return true;
    return APP_CHANNELS.indexOf(ch) !== -1 || ch.indexOf('flutter/') !== 0;
  }
  function bytesOf(buf, len) {
    if (buf === null) return [];
    const n = Math.min(len === undefined ? Java.cast(buf, Buffer).limit() : len, MAX_BYTES);
    const out = new Array(n);
    for (let i = 0; i < n; i++) out[i] = buf.get(i) & 0xff;
    return out;
  }

  function Reader(b) { this.b = b; this.p = 0; }
  Reader.prototype.u8 = function () { return this.b[this.p++]; };
  Reader.prototype.size = function () {
    const v = this.u8();
    if (v < 254) return v;
    if (v === 254) { const r = this.b[this.p] | (this.b[this.p + 1] << 8); this.p += 2; return r; }
    const r = this.b[this.p] | (this.b[this.p + 1] << 8) | (this.b[this.p + 2] << 16) | (this.b[this.p + 3] << 24);
    this.p += 4; return r >>> 0;
  };
  Reader.prototype.align = function (n) { const m = this.p % n; if (m) this.p += n - m; };
  Reader.prototype.utf8 = function (n) {
    const s = this.b.slice(this.p, this.p + n); this.p += n;
    try { return decodeURIComponent(s.map(c => '%' + ('0' + c.toString(16)).slice(-2)).join('')); }
    catch (e) { return String.fromCharCode.apply(null, s); }
  };
  Reader.prototype.value = function (depth) {
    if (this.p >= this.b.length) throw new Error('eof');
    const t = this.u8();
    switch (t) {
      case 0: return null;
      case 1: return true;
      case 2: return false;
      case 3: { const v = this.b[this.p] | (this.b[this.p + 1] << 8) | (this.b[this.p + 2] << 16) | (this.b[this.p + 3] << 24); this.p += 4; return v; }
      case 4: { let v = 0; for (let i = 7; i >= 0; i--) v = v * 256 + this.b[this.p + i]; this.p += 8; return v; }
      case 5: case 7: return this.utf8(this.size());
      case 6: { this.align(8); const dv = new DataView(new Uint8Array(this.b.slice(this.p, this.p + 8)).buffer); this.p += 8; return dv.getFloat64(0, true); }
      case 8: { const n = this.size(); this.p += n; return '<Uint8List ' + n + ' bytes>'; }
      case 9: case 14: { const n = this.size(); this.align(4); this.p += 4 * n; return '<' + (t === 9 ? 'Int32' : 'Float32') + 'List ' + n + '>'; }
      case 10: case 11: { const n = this.size(); this.align(8); this.p += 8 * n; return '<' + (t === 10 ? 'Int64' : 'Float64') + 'List ' + n + '>'; }
      case 12: { const n = this.size(); const a = []; for (let i = 0; i < n; i++) a.push(this.value(depth + 1)); return a; }
      case 13: { const n = this.size(); const o = {}; for (let i = 0; i < n; i++) { const k = this.value(depth + 1); o[String(k)] = this.value(depth + 1); } return o; }
      default: throw new Error('custom type ' + t);
    }
  };
  function fmt(v) { try { return JSON.stringify(v); } catch (e) { return String(v); } }
  function asText(b, max) { return String.fromCharCode.apply(null, b.slice(0, max || 300)).replace(/[^\x20-\x7e]/g, '.'); }

  function decodeCall(b) {
    if (b.length === 0) return null;
    if (b[0] === 0x7b) {
      try { const j = JSON.parse(asText(b, b.length)); if (j.method !== undefined) return { method: j.method, args: fmt(j.args) }; } catch (e) {}
      return null;
    }
    try {
      const r = new Reader(b); const m = r.value(0);
      if (typeof m !== 'string') return null;
      const args = r.p < b.length ? fmt(r.value(0)) : '';
      return { method: m, args: args };
    } catch (e) { return null; }
  }
  function decodeEnvelope(b) {
    if (b.length === 0) return 'null (not implemented / no handler)';
    if (b[0] === 0x5b) return asText(b, 1000);
    try {
      const r = new Reader(b); const tag = r.u8();
      if (tag === 0) return fmt(r.value(0));
      if (tag === 1) return 'ERROR ' + fmt([r.value(0), r.value(0), r.value(0)]);
    } catch (e) {}
    return asText(b);
  }
  function encodeSuccess(v) {
    const out = [0];
    if (v === null) out.push(0);
    else if (v === true) out.push(1);
    else if (v === false) out.push(2);
    else if (typeof v === 'number') { out.push(3, v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff); }
    else {
      const s = unescape(encodeURIComponent(String(v)));
      out.push(7);
      if (s.length < 254) out.push(s.length); else out.push(254, s.length & 0xff, (s.length >> 8) & 0xff);
      for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
    }
    const buf = ByteBuffer.allocateDirect(out.length);
    out.forEach(x => buf.put(x > 127 ? x - 256 : x));
    return [buf, out.length];
  }

  JNI.handlePlatformMessage.overloads.forEach(function (ov) {
    ov.implementation = function () {
      const ch = arguments[0], msg = arguments[1], replyId = arguments[2];
      const b = bytesOf(msg);
      const call = decodeCall(b);
      const label = call ? ch + ' :: ' + call.method : ch;
      if (call) {
        const o = OVERRIDES[ch];
        if (o && Object.prototype.hasOwnProperty.call(o, call.method) && replyId !== 0) {
          console.log('[dart->native] ' + label + '(' + call.args + ')  => OVERRIDDEN ' + fmt(o[call.method]));
          const enc = encodeSuccess(o[call.method]);
          this.invokePlatformMessageResponseCallback(replyId, enc[0], enc[1]);
          try { if (arguments.length > 3) this.cleanupMessageData(arguments[3]); } catch (e) {}
          return;
        }
      }
      if (show(ch)) {
        console.log('[dart->native] ' + label + (call ? '(' + call.args + ')' : '  ' + asText(b)));
        if (replyId !== 0) pending[replyId] = label;
      }
      return ov.apply(this, arguments);
    };
  });

  JNI.invokePlatformMessageResponseCallback.overloads.forEach(function (ov) {
    ov.implementation = function () {
      const id = arguments[0];
      if (pending[id] !== undefined) {
        const len = arguments.length > 2 ? arguments[2] : undefined;
        console.log('[native->dart] reply  ' + pending[id] + ' => ' + decodeEnvelope(bytesOf(arguments[1], len)));
        delete pending[id];
      }
      return ov.apply(this, arguments);
    };
  });

  JNI.dispatchPlatformMessage.overloads.forEach(function (ov) {
    ov.implementation = function () {
      const ch = arguments[0];
      if (show(ch)) {
        const len = arguments.length > 2 ? arguments[2] : undefined;
        const b = bytesOf(arguments[1], len);
        const call = decodeCall(b);
        console.log('[native->dart] ' + ch + (call ? ' :: ' + call.method + '(' + call.args + ')' : '  ' + asText(b)));
      }
      return ov.apply(this, arguments);
    };
  });
  console.log('[*] platform-channel tracer ready (' + APP_CHANNELS.length + ' app channels known)');
}

function findFlutter() {
  try { if (Process.findModuleByName('libflutter.so')) return true; } catch (e) {}
  return Process.enumerateModules().some(m => m.name === 'libflutter.so');
}
function waitAndInstall() {
  if (!findFlutter()) { setTimeout(waitAndInstall, 50); return; }
  Java.perform(function () {
    const app = Java.use('android.app.ActivityThread').currentApplication();
    if (app !== null) Java.classFactory.loader = app.getClassLoader();
    try { install(); } catch (e) { console.log('[!] ' + e); }
  });
}
if (!findFlutter()) console.log('[*] waiting for libflutter.so ...');
waitAndInstall();
"""

NET_RECON = COMPAT + r"""
function sockaddr(p) {
  const fam = p.readU16();
  if (fam === 2) {
    const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
    const ip = [4, 5, 6, 7].map(i => p.add(i).readU8()).join('.');
    return ip + ':' + port;
  }
  if (fam === 10 || fam === 30) {
    const port = (p.add(2).readU8() << 8) | p.add(3).readU8();
    const a = []; for (let i = 0; i < 16; i++) a.push(p.add(8 + i).readU8());
    const mapped = a.slice(0, 10).every(x => x === 0) && a[10] === 0xff && a[11] === 0xff;
    if (mapped) return a.slice(12).join('.') + ':' + port;
    const b = []; for (let i = 0; i < 16; i += 2) b.push(((a[i] << 8) | a[i + 1]).toString(16));
    return '[' + b.join(':') + ']:' + port;
  }
  return null;
}
const seen = {};
const connect = findExport('connect');
Interceptor.attach(connect, {
  onEnter(args) { this.dst = sockaddr(args[1]); },
  onLeave() {
    if (this.dst && !seen[this.dst]) { seen[this.dst] = 1; console.log('[connect] ' + this.dst); }
  }
});
const flutter = findModule('libflutter.so') || findModule('Flutter');
console.log('[*] net recon ready; flutter engine ' + (flutter ? 'loaded at ' + flutter.base : 'not loaded yet'));
"""

TLS_HINT = """# Intercepting this Flutter app's traffic

Flutter does **not** use the platform HTTP stack. `dart:io` ships its own
BoringSSL inside the engine (`libflutter.so` / `Flutter.framework`), which:

1. ignores the system / Wi-Fi proxy setting, and
2. ignores user-installed CA certificates (and network_security_config).

So a stock Burp setup sees nothing. You need **both**:

* **Redirect at the network layer.** Android (root): `iptables -t nat -A OUTPUT -p tcp
  --dport 443 -m owner --uid-owner <app uid> -j DNAT --to <burp-ip>:8080`, or a VPN-based
  transparent proxy. In Burp enable *Proxy > Options > Support invisible proxying*.
  `net_recon.js` in this folder shows which hosts/ports the app actually connects to.
* **Disable BoringSSL certificate verification** in the engine:
  {script}
  - NVISO's maintained script: https://github.com/NVISOsecurity/disable-flutter-tls-verification
    `frida -U -f {package} -l disable-flutter-tls.js`
  - or patch the engine statically with reFlutter (https://github.com/Impact-I/reFlutter).

{extra}
"""


def method_channel_script(app_channels: list[str]) -> str:
    return METHOD_CHANNELS.replace("__APP_CHANNELS__", json.dumps(app_channels)).lstrip()


def net_recon_script() -> str:
    return NET_RECON.lstrip()


def tls_hint(package: str, protections: list[dict], uses_native_http: bool, located: str = "") -> str:
    extra = []
    if uses_native_http:
        names = ", ".join(uses_native_http) if isinstance(uses_native_http, list) else "native HTTP plugins"
        extra.append(f"**Part of this app's traffic bypasses dart:io** ({names}): these plugins call the "
                     "native Android/iOS SDKs, whose TLS runs in the platform stack (Conscrypt / "
                     "NSURLSession). `flutter_tls_bypass.js` also hooks Conscrypt's TrustManagerImpl and "
                     "okhttp3 CertificatePinner; on a rooted device installing your CA in the system store "
                     "works too. On iOS you need SecTrust hooks.")
    for p in protections:
        if p["kind"] == "rasp":
            extra.append(f"**{p['name']}** detected ({p['source']}): expect root/Frida detection. {p['note']}")
        elif p["kind"] == "pinning":
            extra.append(f"Pinning signal: **{p['name']}** ({p['source']}). {p['note']}")
    script = (f"- **`flutter_tls_bypass.js` (generated for this exact engine, {located})**: hooks "
              "ssl_crypto_x509_session_verify_cert_chain and forces it to succeed.\n    "
              f"`frida -U -f {package or '<package>'} -l flutter_tls_bypass.js`"
              if located else "- the verification function could not be located automatically in this engine;")
    return TLS_HINT.replace("{script}", script).replace("{package}", package or "<package>").replace(
        "{extra}", "\n\n".join(extra) if extra else "No pinning or RASP signals beyond the default engine "
                                                     "behaviour were found.")


def blutter_hooks(functions: list, limit: int = 60) -> str:
    rows = [{"name": f"{f.cls}.{f.name}", "addr": hex(f.addr), "file": f.file} for f in functions[:limit]]
    return COMPAT.lstrip() + """
const TARGETS = """ + json.dumps(rows, indent=2) + """;
function install() {
  const app = findModule('libapp.so') || findModule('App');
  if (!app) { setTimeout(install, 300); return; }
  TARGETS.forEach(t => {
    try {
      Interceptor.attach(app.base.add(ptr(t.addr)), { onEnter() { console.log('[dart] ' + t.name); } });
    } catch (e) { console.log('[!] ' + t.name + ': ' + e); }
  });
  console.log('[*] ' + TARGETS.length + ' Dart function hooks installed at libapp base ' + app.base);
}
install();
"""


TLS_BYPASS = COMPAT + r"""
const TARGETS = __TARGETS__;

function hexAt(p, n) {
  const b = new Uint8Array(p.readByteArray(n));
  return Array.from(b, x => ('0' + x.toString(16)).slice(-2)).join('');
}

function install(mod) {
  const t = TARGETS[Process.arch];
  if (!t) { console.log('[!] no offset for arch ' + Process.arch + ' (have: ' + Object.keys(TARGETS) + ')'); return; }
  const addr = mod.base.add(ptr(t.offset));
  const want = t.prologue.slice(0, 32);
  const got = hexAt(addr, want.length / 2);
  if (got !== want) {
    console.log('[!] bytes at ' + t.offset + ' do not match (' + got + ' != ' + want + '): different engine build, not hooking');
    return;
  }
  let calls = 0;
  Interceptor.attach(addr, {
    onLeave(retval) {
      calls++;
      if (retval.toInt32() !== 1) console.log('[tls] verify_cert_chain returned ' + retval.toInt32() + ' -> forced 1 (call #' + calls + ')');
      else if (calls <= 3) console.log('[tls] verify_cert_chain ok (call #' + calls + ')');
      retval.replace(1);
    }
  });
  console.log('[*] ssl_crypto_x509_session_verify_cert_chain hooked at ' + mod.name + '+' + t.offset + ' (' + addr + ')');
}

function wait() {
  const m = findModule('libflutter.so') || findModule('Flutter');
  if (m) install(m); else setTimeout(wait, 50);
}
wait();

const JAVA_BYPASS = true;
if (JAVA_BYPASS && typeof Java !== 'undefined' && Java.available) {
  Java.perform(function () {
    try {
      const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TMI.verifyChain.overloads.forEach(function (ov) {
        ov.implementation = function () {
          console.log('[tls-java] TrustManagerImpl.verifyChain(' + (arguments[2] || '?') + ') -> accepted');
          return arguments[0];
        };
      });
      console.log('[*] Conscrypt TrustManagerImpl.verifyChain hooked');
    } catch (e) { console.log('[!] TrustManagerImpl: ' + e.message); }
    try {
      const CP = Java.use('okhttp3.CertificatePinner');
      CP.check.overloads.forEach(function (ov) {
        ov.implementation = function () { console.log('[tls-java] okhttp3 CertificatePinner.check(' + arguments[0] + ') -> skipped'); };
      });
      console.log('[*] okhttp3.CertificatePinner hooked');
    } catch (e) { }
  });
}
"""


def tls_bypass_script(targets: dict[str, dict]) -> str:
    return TLS_BYPASS.replace("__TARGETS__", json.dumps(targets, indent=2)).lstrip()


ANTI_DETECTION = r"""
const ENABLE = __ENABLE__;

const SPOOF_DEVICE = {
  FINGERPRINT: 'google/panther/panther:14/UQ1A.240205.002/11224170:user/release-keys',
  MODEL: 'Pixel 7', MANUFACTURER: 'Google', BRAND: 'google', DEVICE: 'panther',
  PRODUCT: 'panther', HARDWARE: 'panther', BOARD: 'panther', TAGS: 'release-keys',
};
const ROOT_PATH = /(\/su$|\/su\/|magisk|busybox|Superuser|supersu|xposed|lsposed|frida|\/data\/adb|kernelsu|daemonsu)/i;
const EMU_PATH = /(qemu|goldfish|ranchu|genyd|vbox|nox|ttVM|microvirt|bluestacks|andy)/i;
const ROOT_PKGS = /^(com\.topjohnwu\.magisk|io\.github\.huskydg\.magisk|me\.weishu\.kernelsu|eu\.chainfire\.supersu|com\.noshufou\.android\.su|com\.koushikdutta\.superuser|com\.thirdparty\.superuser|com\.yellowes\.su|com\.kingroot\.kinguser|com\.kingo\.root|de\.robv\.android\.xposed\.installer|org\.lsposed\.manager|com\.saurik\.substrate|com\.devadvance\.rootcloak2?|com\.amphoras\.hidemyroot|com\.formyhm\.hideroot|com\.chelpus\.lackypatch|com\.dimonvideo\.luckypatcher|re\.frida\.server)$/;
const FRIDA_LINE = /(frida|gum-js|gmain|gdbus|linjector|gadget)/i;

const seen = {};
function log(k, msg) { if (!seen[k]) { seen[k] = 1; console.log('[anti] ' + msg); } }

Java.perform(function () {
  function hookAll(cls, method, impl) {
    try {
      const C = Java.use(cls);
      if (C[method] === undefined) return false;
      C[method].overloads.forEach(function (ov) { ov.implementation = impl(ov); });
      return true;
    } catch (e) { console.log('[!] ' + cls + '.' + method + ': ' + e.message); return false; }
  }

  if (ENABLE.adb || ENABLE.developer) {
    const KEYS = {};
    if (ENABLE.adb) { KEYS['adb_enabled'] = 0; KEYS['adb_wifi_enabled'] = 0; }
    if (ENABLE.developer) { KEYS['development_settings_enabled'] = 0; }
    ['android.provider.Settings$Global', 'android.provider.Settings$Secure'].forEach(function (cls) {
      ['getInt', 'getLong', 'getString'].forEach(function (m) {
        hookAll(cls, m, function (ov) {
          return function () {
            const name = arguments[1];
            if (Object.prototype.hasOwnProperty.call(KEYS, name)) {
              log(cls + name, name + ' -> ' + KEYS[name] + '  (' + cls.split('$')[1] + '.' + m + ')');
              return m === 'getString' ? String(KEYS[name]) : KEYS[name];
            }
            return ov.apply(this, arguments);
          };
        });
      });
    });
  }

  if (ENABLE.debugger) {
    hookAll('android.os.Debug', 'isDebuggerConnected', function () {
      return function () { log('dbg1', 'Debug.isDebuggerConnected -> false'); return false; };
    });
    hookAll('android.os.Debug', 'waitingForDebugger', function () {
      return function () { log('dbg2', 'Debug.waitingForDebugger -> false'); return false; };
    });
  }

  if (ENABLE.root || ENABLE.emulator) {
    const pathRx = ENABLE.root && ENABLE.emulator ? new RegExp(ROOT_PATH.source + '|' + EMU_PATH.source, 'i')
                                                   : (ENABLE.root ? ROOT_PATH : EMU_PATH);
    ['exists', 'canRead', 'canExecute', 'isFile', 'isDirectory'].forEach(function (m) {
      hookAll('java.io.File', m, function (ov) {
        return function () {
          const p = this.getAbsolutePath();
          if (pathRx.test(p)) { log('f' + m + p, 'File.' + m + '(' + p + ') -> false'); return false; }
          return ov.apply(this, arguments);
        };
      });
    });
  }
  if (ENABLE.root) {
    const IOException = Java.use('java.io.IOException');
    hookAll('java.lang.Runtime', 'exec', function (ov) {
      return function () {
        const a = arguments[0];
        const cmd = (a !== null && a.toString().indexOf('[Ljava') === 0) ? Java.cast(a, Java.use('[Ljava.lang.String;')) : a;
        const s = cmd === null ? '' : (Array.isArray(cmd) ? cmd.join(' ') : cmd.toString());
        if (/(^|\s|\/)(su|magisk|busybox)(\s|$)|which su/.test(s)) {
          log('exec' + s, 'Runtime.exec(' + s + ') -> IOException');
          throw IOException.$new('Cannot run program');
        }
        return ov.apply(this, arguments);
      };
    });
    const NNF = Java.use('android.content.pm.PackageManager$NameNotFoundException');
    hookAll('android.app.ApplicationPackageManager', 'getPackageInfo', function (ov) {
      return function () {
        const name = arguments[0];
        if (typeof name === 'string' && ROOT_PKGS.test(name)) {
          log('pkg' + name, 'getPackageInfo(' + name + ') -> NameNotFound');
          throw NNF.$new(name);
        }
        return ov.apply(this, arguments);
      };
    });
  }

  try {
    const Build = Java.use('android.os.Build');
    if (ENABLE.root) { Build.TAGS.value = 'release-keys'; log('tags', 'Build.TAGS -> release-keys'); }
    if (ENABLE.emulator) {
      Object.keys(SPOOF_DEVICE).forEach(function (k) { try { Build[k].value = SPOOF_DEVICE[k]; } catch (e) {} });
      log('build', 'Build.* -> ' + SPOOF_DEVICE.MODEL + ' (' + SPOOF_DEVICE.FINGERPRINT + ')');
      hookAll('android.os.SystemProperties', 'get', function (ov) {
        return function () {
          const k = arguments[0];
          if (/^(ro\.kernel\.qemu.*|ro\.boot\.qemu|init\.svc\.qemu.*|qemu\..*|ro\.hardware\.audio\.primary)$/.test(k)) {
            log('sp' + k, 'SystemProperties.get(' + k + ') -> ""'); return arguments.length > 1 ? arguments[1] : '';
          }
          if (k === 'ro.hardware' || k === 'ro.product.board') { log('sp' + k, k + ' -> ' + SPOOF_DEVICE.HARDWARE); return SPOOF_DEVICE.HARDWARE; }
          return ov.apply(this, arguments);
        };
      });
    }
  } catch (e) { console.log('[!] Build: ' + e.message); }

  if (ENABLE.hooking) {
    hookAll('java.io.BufferedReader', 'readLine', function (ov) {
      return function () {
        let line = ov.apply(this, arguments);
        while (line !== null && FRIDA_LINE.test(line)) { log('maps', 'hid frida line from BufferedReader.readLine'); line = ov.apply(this, arguments); }
        return line;
      };
    });
  }

  if (ENABLE.mocklocation) {
    ['isFromMockProvider', 'isMock'].forEach(function (m) {
      hookAll('android.location.Location', m, function () { return function () { log('mock' + m, 'Location.' + m + ' -> false'); return false; }; });
    });
  }

  if (ENABLE.devicelock) {
    ['isKeyguardSecure', 'isDeviceSecure'].forEach(function (m) {
      hookAll('android.app.KeyguardManager', m, function () { return function () { log('kg' + m, 'KeyguardManager.' + m + ' -> true'); return true; }; });
    });
  }

  if (ENABLE.screen) {
    hookAll('android.view.Window', 'setFlags', function (ov) {
      return function (flags, mask) {
        if (flags & 0x2000) { log('fs', 'Window FLAG_SECURE stripped'); flags &= ~0x2000; }
        return ov.call(this, flags, mask);
      };
    });
    hookAll('android.view.Window', 'addFlags', function (ov) {
      return function (flags) {
        if (flags & 0x2000) { log('fs', 'Window FLAG_SECURE stripped'); flags &= ~0x2000; }
        return ov.call(this, flags);
      };
    });
    hookAll('android.view.SurfaceView', 'setSecure', function (ov) {
      return function () { log('sv', 'SurfaceView.setSecure -> false'); return ov.call(this, false); };
    });
  }

  if (ENABLE.network) {
    hookAll('android.net.NetworkCapabilities', 'hasTransport', function (ov) {
      return function (t) { if (t === 4) { log('vpn', 'hasTransport(TRANSPORT_VPN) -> false'); return false; } return ov.call(this, t); };
    });
  }

  if (ENABLE.integrity) {
    hookAll('android.app.ApplicationPackageManager', 'getInstallerPackageName', function () {
      return function () { log('inst', 'getInstallerPackageName -> com.android.vending'); return 'com.android.vending'; };
    });
  }
  console.log('[*] anti-detection ready: ' + Object.keys(ENABLE).filter(function (k) { return ENABLE[k]; }).join(', '));
});
"""

ANTI_KEYS = ("root", "hooking", "debugger", "adb", "developer", "emulator", "mocklocation", "devicelock",
             "screen", "network", "integrity")


def anti_detection_script(categories: dict[str, str]) -> str:
    enable = {k: categories.get(k) in ("enforcement-candidate", "weak-signal") for k in ANTI_KEYS}
    return ANTI_DETECTION.replace("__ENABLE__", json.dumps(enable, indent=2)).lstrip()
