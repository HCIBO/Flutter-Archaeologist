import struct
import zipfile

import pytest

from conftest import FIXTURES
from flutter_archaeologist import frida, tlsfind


def engines():
    p = FIXTURES / "demo-release.apk"
    if not p.exists():
        pytest.skip("fixtures not built")
    z = zipfile.ZipFile(p)
    return {n.split("/")[1]: z.read(n) for n in z.namelist() if n.endswith("/libflutter.so")}


@pytest.mark.parametrize("abi", ["arm64-v8a", "x86_64"])
def test_finds_verify_cert_chain(abi):
    data = engines()[abi]
    t = tlsfind.find(data)
    assert t.status == "found"
    roles = {c["role"] for c in t.candidates}
    assert roles == {"X509_VERIFY_PARAM_lookup", "session_verify_cert_chain"}
    off = t.offset
    if abi == "arm64-v8a":
        first = struct.unpack_from("<I", data, off)[0]
        assert first in (0xD503233F,) or first & 0xFFC003E0 == 0xA98003E0 or first & 0xFF0003FF == 0xD10003FF
    else:
        assert data[off] in (0x55, 0x41, 0x53, 0x48)


def test_rejects_non_elf():
    assert tlsfind.find(b"not an elf").status == "unsupported"


def test_bypass_script_embeds_targets():
    js = frida.tls_bypass_script({"arm64": {"offset": "0x6f4928", "prologue": "3f2303d5ffc301d1"}})
    assert '"offset": "0x6f4928"' in js and "retval.replace(1)" in js
