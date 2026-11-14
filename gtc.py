#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import random
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#  config
GTC_BASE = "https://pbssrv-centralevents.com"
VFK_BASE = "https://api.verifykit.com"
HMAC_KEY = "31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762"
VFK_HMAC_KEY = "3452235d713252604a35562d325f765238695738485863672a705e6841544d3c7e6e45463028266f372b544e596f3829236b392825262e534a7e774f37653932"
VFK_CLIENT_KEY = "bhvbd7ced119dc6ad6a0b35bd3cf836555d6f71930d9e5a405f32105c790d"
VFK_FINAL_KEY = "bd48d8c25293cfb537619cc93ae3d6e372eb2ddfffff4ab0eb000777144c7bfa"

APP_VERSION = "8.4.0"
ANDROID_OS = "android 9"
LANG = "en_US"
COUNTRY = "id"
DEVICE_NAME = "SM-G977N"
TIME_ZONE = "Asia/Bangkok"
BUNDLE_ID = "app.source.getcontact"
CARRIER = ("510", "Indosat Ooredoo", "01")

# Diffie-Hellman params
DH_P = 900719898367
DH_G = 7

CONFIG_DIR = Path(os.environ.get("GTC_CONFIG_DIR", Path.home() / ".config" / "gtc"))
CRED_FILE = CONFIG_DIR / "credentials.json"
RESULTS_DIR = Path(os.environ.get("GTC_RESULTS_DIR", Path(__file__).resolve().parent / "results"))


class GtcError(Exception):
    pass


#  crypto
def _sig(ts: str, message: str, key_hex: str) -> str:
    mac = hmac.new(bytes.fromhex(key_hex), f"{ts}-{message}".encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def _pad(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def encrypt(data: str, key_hex: str) -> str:
    enc = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
    return base64.b64encode(enc.update(_pad(data.encode())) + enc.finalize()).decode()


def decrypt(data: str, key_hex: str) -> str:
    dec = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).decryptor()
    out = dec.update(base64.b64decode(data)) + dec.finalize()
    return out[: -out[-1]].decode()


def dh_keypair() -> tuple[int, int]:
    priv = secrets.randbelow(10**8 - 10**6) + 10**6
    return priv, pow(DH_G, priv, DH_P)


def dh_final_key(priv: int, server_pub: int) -> str:
    return hashlib.sha256(str(pow(int(server_pub), priv, DH_P)).encode()).hexdigest()


def _ts() -> str:
    return str(int(time.time() * 1000))


def new_device_id() -> str:
    return secrets.token_hex(8)


#  http
def _post(url: str, body: str, headers: dict, timeout: int = 25) -> requests.Response:
    return requests.post(url, data=body, headers=headers, timeout=timeout)


def gtc_call(endpoint: str, payload: dict, *, token: str, final_key: str,
             device_id: str, encrypted: bool = True) -> tuple[int, dict]:
    """POST to a GetContact endpoint. Returns (http_code, decrypted_json)."""
    raw = json.dumps(payload, ensure_ascii=False)
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION,
        "x-client-device-id": device_id,
        "x-lang": LANG,
        "x-req-timestamp": ts,
        "x-country-code": COUNTRY,
        "x-encrypted": "1" if encrypted else "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    }
    if token:
        headers["x-token"] = token
    body = json.dumps({"data": encrypt(raw, final_key)}) if encrypted else raw
    r = _post(GTC_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if encrypted and "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], final_key))
    return r.status_code, parsed


def vfk_call(endpoint: str, payload: dict, device_id: str) -> tuple[int, dict]:
    """VerifyKit call — fixed version (compact JSON + App-Version 8.16.0)."""
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    ts = _ts()
    headers = {
        "Content-Type": "application/json",
        "X-VFK-Client-Device-Id": device_id,
        "X-VFK-Client-Key": VFK_CLIENT_KEY,
        "X-VFK-Sdk-Version": "0.11.4",
        "X-VFK-Os": "android 9.0",
        "X-VFK-App-Version": "8.16.0",         
        "X-VFK-Encrypted": "1",
        "X-VFK-Lang": "in_ID",
        "X-VFK-Req-Timestamp": ts,
        "X-VFK-Req-Signature": _sig(ts, raw, VFK_HMAC_KEY),
    }
    body = json.dumps({"data": encrypt(raw, VFK_FINAL_KEY)}, separators=(",", ":"))
    r = _post(VFK_BASE + endpoint, body, headers)
    try:
        parsed = r.json()
    except ValueError:
        raise GtcError(f"{endpoint}: non-JSON response (HTTP {r.status_code})")
    if "data" in parsed:
        parsed = json.loads(decrypt(parsed["data"], VFK_FINAL_KEY))
    return r.status_code, parsed


def dig(obj, path, default=None):
    for k in path.split("."):
        if not isinstance(obj, dict) or k not in obj:
            return default
        obj = obj[k]
    return obj


#  store
def load_store() -> dict:
    if not CRED_FILE.exists():
        return {"active": None, "credentials": {}}
    return json.loads(CRED_FILE.read_text("utf-8"))


def save_store(store: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CRED_FILE.write_text(json.dumps(store, indent=2), "utf-8")
    try:
        os.chmod(CRED_FILE, 0o600)
    except OSError:
        pass


def get_cred(store: dict, name: str | None) -> tuple[str, dict]:
    name = name or store.get("active")
    creds = store.get("credentials", {})
    if not name or name not in creds:
        raise GtcError("Tidak ada akun aktif. Tambahkan/pilih akun terlebih dahulu melalui menu 'Lihat/ganti akun tersimpan' atau 'Tambah akun baru'.")
    return name, creds[name]


def normalize_phone(raw: str) -> str:
    p = re.sub(r"[^\d+]", "", raw.strip())
    if p.startswith("+"):
        return p
    if p.startswith("0"):
        return "+62" + p[1:]
    if p.startswith("62"):
        return "+" + p
    raise GtcError(f"Invalid phone number: {raw}")


#  features logic
def api_search(cred: dict, phone: str, source: str) -> dict:
    endpoint = "/v2.8/number-detail" if source == "tags" else "/v2.8/search"
    payload = {
        "countryCode": COUNTRY,
        "phoneNumber": phone,
        "source": "profile" if source == "tags" else "search",
        "token": cred["token"],
    }
    code, body = gtc_call(endpoint, payload, token=cred["token"],
                          final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    meta = dig(body, "meta.httpStatusCode")
    if code != 200 or meta != 200:
        raise GtcError(f"HTTP {code}/{meta}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def api_subscription(cred: dict) -> dict:
    code, body = gtc_call("/v2.8/subscription", {"token": cred["token"]},
                          token=cred["token"], final_key=cred["finalKey"],
                          device_id=cred["clientDeviceId"])
    if code != 200:
        raise GtcError(f"HTTP {code}: {dig(body, 'meta.errorMessage', 'unknown error')}")
    return body


def show_captcha(b64_image: str) -> Path:
    path = Path(tempfile.gettempdir()) / f"gtc_captcha_{int(time.time())}.jpg"
    path.write_bytes(base64.b64decode(b64_image))
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:
        pass
    return path


#  Direct Menu Functions
def menu_search(source_type: str):
    store = load_store()
    _, cred = get_cred(store, None)
    raw_phone = input("Masukkan nomor telepon: ").strip()
    phone = normalize_phone(raw_phone)
    print(f"\nMencari {phone}...")
    body = api_search(cred, phone, source_type)
    
    print("\n--- HASIL PENCARIAN ---")
    profile = dig(body, "result.profile")
    if profile:
        for k in ("displayName", "name", "surname", "phoneNumber", "displayNumber", "tagCount", "email"):
            print(f"  {k:<14}: {profile.get(k) or '-'}")
    tags = dig(body, "result.tags")
    if tags:
        print(f"  tags ({len(tags)}):")
        for t in tags:
            print(f"    - {t.get('tag')}  x{t.get('count', '')}")
    if not profile and not tags:
        print(json.dumps(body, indent=2, ensure_ascii=False))
    print("-----------------------")


def menu_quota():
    store = load_store()
    name, cred = get_cred(store, None)
    body = api_subscription(cred)
    u = dig(body, "result.subscriptionInfo.usage") or {}
    print(f"\n--- KUOTA AKUN [{name}] ---")
    for key in ("search", "numberDetail"):
        d = u.get(key) or {}
        print(f"  {key:<13}: {d.get('remainingCount', '?')}/{d.get('limit', '?')} remaining")
    print(f"  renewDate    : {dig(body, 'result.subscriptionInfo.renewDate', '-')}")
    print("--------------------------")


def menu_batch():
    store = load_store()
    _, cred = get_cred(store, None)
    csv_path = input("Masukkan path file CSV: ").strip()
    if not os.path.exists(csv_path):
        print("File CSV tidak ditemukan!")
        return
    
    with open(csv_path, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        print("File CSV kosong!")
        return
        
    header = rows[0]
    col = 0
    if any(h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor") for h in header):
        col = next(i for i, h in enumerate(header)
                   if h.strip().lower() in ("phone", "phone_number", "phonenumber", "nomor"))
        rows = rows[1:]
        
    print("\nMemulai pencarian batch...")
    for row in rows:
        if not row or not row[col].strip():
            continue
        raw = row[col].strip()
        try:
            phone = normalize_phone(raw)
            body = api_search(cred, phone, "tags")
            prof = dig(body, "result.profile") or {}
            tags = [t.get("tag", "") for t in (dig(body, "result.tags") or [])]
            print(f"[OK] {phone} -> {prof.get('displayName', 'Tanpa Nama')} | Tags: {len(tags)}")
        except Exception as e:
            print(f"[FAIL] {raw}: {e}")
        time.sleep(1.5)
    print("Batch selesai.")


def menu_captcha():
    store = load_store()
    _, cred = get_cred(store, None)
    common = dict(token=cred["token"], final_key=cred["finalKey"], device_id=cred["clientDeviceId"])
    code, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
    image = dig(body, "result.image")
    if not image:
        print(f"Tidak ada captcha (HTTP {code}). Akun mungkin tidak terblokir.")
        return
    while True:
        path = show_captcha(image)
        print(f"Gambar captcha disimpan di: {path}")
        answer = input("Masukkan kode captcha (kosong = refresh, 'q' = kembali): ").strip()
        if answer.lower() == "q":
            break
        if not answer:
            _, body = gtc_call("/v2.8/refresh-code", {"token": cred["token"]}, **common)
            image = dig(body, "result.image") or image
            continue
        code, body = gtc_call("/v2.8/verify-code",
                              {"validationCode": answer, "token": cred["token"]}, **common)
        if code == 200 and dig(body, "meta.httpStatusCode") == 200:
            print("Captcha berhasil diverifikasi!")
            break
        print("Kode salah, captcha baru dibuat.")
        image = dig(body, "result.image") or image


def menu_cred_list():
    store = load_store()
    creds = store.get("credentials", {})
    if not creds:
        print("\nBelum ada akun tersimpan.")
        return
    print("\n--- DAFTAR AKUN TERSIMPAN ---")
    for name, c in creds.items():
        mark = "*" if name == store.get("active") else " "
        print(f"{mark} {name:<20} | {c.get('phoneNumber', '-'):<15} | {c.get('description', '')}")
    print("-----------------------------")
    
    sub_opt = input("\nKetik nama akun untuk dijadikan aktif (atau kosongkan untuk kembali): ").strip()
    if sub_opt:
        if sub_opt in creds:
            store["active"] = sub_opt
            save_store(store)
            print(f"Akun aktif berhasil diubah ke: {sub_opt}")
        else:
            print("Nama akun tidak ditemukan!")


def menu_generate():
    raw_phone = input("Masukkan nomor WhatsApp untuk verifikasi (misal 08xxxxxxxx): ").strip()
    phone = normalize_phone(raw_phone)
    device_id = new_device_id()
    priv, pub = dh_keypair()

    print("Mendaftarkan perangkat...")
    ts = _ts()
    reg_body = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY, "deepLink": None,
        "deviceName": DEVICE_NAME, "deviceType": "Android", "email": None,
        "notificationToken": "", "oldToken": None, "peerKey": pub,
        "timeZone": TIME_ZONE, "token": "",
    }
    raw = json.dumps(reg_body, ensure_ascii=False)
    r = _post(GTC_BASE + "/v2.8/register", raw, {
        "Content-Type": "application/json", "x-os": ANDROID_OS,
        "x-app-version": APP_VERSION, "x-client-device-id": device_id, "x-lang": LANG,
        "x-req-timestamp": ts, "x-country-code": COUNTRY, "x-encrypted": "0",
        "x-req-signature": _sig(ts, raw, HMAC_KEY),
    })
    if r.status_code != 201:
        print(f"Gagal register: HTTP {r.status_code} {r.text[:200]}")
        return
    reg = r.json()
    token = dig(reg, "result.token")
    server_key = dig(reg, "result.serverKey")
    if not token or not server_key:
        print("Register gagal: token/serverKey tidak ada")
        return
    final_key = dh_final_key(priv, server_key)

    common = dict(token=token, final_key=final_key, device_id=device_id)
    base = {
        "carrierCountryCode": CARRIER[0], "carrierName": CARRIER[1],
        "carrierNetworkCode": CARRIER[2], "countryCode": COUNTRY,
        "deviceName": DEVICE_NAME, "notificationToken": "", "timeZone": TIME_ZONE,
        "token": token,
    }
    steps = [
        ("/v2.8/init-basic", base, 201),
        ("/v2.8/ad-settings", {"source": "init", "token": token}, 200),
        ("/v2.8/init-intro", {**base, "hasRouting": False}, 201),
        ("/v2.8/email-code-validate/start",
         {"email": f"user{random.randint(10**7, 10**8 - 1)}@gmail.com",
          "fullName": f"User{random.randint(1000, 999999)}", "token": token}, 200),
        ("/v2.8/country", {"countryCode": COUNTRY.upper(), "token": token}, 200),
        ("/v2.8/validation-start",
         {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token}, 200),
    ]
    for endpoint, payload, want in steps:
        code, body = gtc_call(endpoint, payload, **common)
        if code != want:
            print(f"Inisialisasi gagal di {endpoint} (HTTP {code})")
            return

    # VerifyKit
    vfk_call("/v2.0/init", {
        "isCallPermissionGranted": True, "countryCode": "ID", "deviceName": DEVICE_NAME,
        "installedApps": '{"whatsapp":0,"telegram":0,"viber":0}',
        "outsideCountryCode": "ID", "outsidePhoneNumber": raw_phone,
        "timezone": TIME_ZONE, "bundleId": BUNDLE_ID,
    }, device_id)

    vfk_call("/v2.0/country", {"countryCode": "ID", "bundleId": BUNDLE_ID}, device_id)

    code, body = vfk_call("/v2.0/start", {
        "countryCode": "ID", "mcc": CARRIER[0], "mnc": CARRIER[2],
        "phoneNumber": phone, "app": "whatsapp", "bundleId": BUNDLE_ID,
    }, device_id)
    
    deeplink = dig(body, "result.deeplink")
    reference = dig(body, "result.reference")
    if not deeplink or not reference:
        print("Gagal mendapatkan link verifikasi WhatsApp.")
        return

    gtc_call("/v2.8/validation-start",
             {"app": "verifykit", "countryCode": COUNTRY, "notificationToken": "", "token": token},
             **common)

    print("\n[!] Kirim pesan verifikasi WhatsApp melalui link berikut:")
    print(f"  Link : {deeplink}")
    input("\nTekan Enter jika pesan WhatsApp sudah terkirim dan bercentang... ")

    code, body = vfk_call("/v2.0/check", {"reference": reference, "bundleId": BUNDLE_ID}, device_id)
    session_id = dig(body, "result.sessionId")
    if not session_id:
        print("Verifikasi belum selesai / gagal.")
        return

    code, body = gtc_call("/v2.8/verifykit-result", {"sessionId": session_id, "token": token}, **common)
    validation_date = dig(body, "result.validationDate")
    if not validation_date:
        print("Gagal mengambil hasil verifykit.")
        return

    store = load_store()
    name = phone
    store.setdefault("credentials", {})[name] = {
        "description": f"Generated {validation_date}",
        "phoneNumber": phone,
        "clientDeviceId": device_id,
        "finalKey": final_key,
        "token": token,
        "validationDate": validation_date,
    }
    store["active"] = name
    save_store(store)
    print(f"\nBerhasil! Akun tersimpan dengan nama '{name}'.")


BANNER = r"""
 ██████╗ ███████╗████████╗ ██████╗ ██████╗ ███╗   ██╗████████╗ █████╗  ██████╗████████╗
██╔════╝ ██╔════╝╚══██╔══╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██╔════╝╚══██╔══╝
██║  ███╗█████╗     ██║   ██║     ██║   ██║██╔██╗ ██║   ██║   ███████║██║        ██║   
██║   ██║██╔══╝     ██║   ██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██║██║        ██║   
╚██████╔╝███████╗   ██║   ╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║╚██████╗   ██║   
 ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝   ╚═╝                                                                            
Credits By RendiSec 
"""

MENU = [
    ("Cari profil nomor        (nama pemilik)", "profile"),
    ("Cari tag nomor           (nama tersimpan orang lain)", "tags"),
    ("Sisa kuota akun", "quota"),
    ("Cari banyak nomor dari file CSV", "batch"),
    ("Buka blokir / captcha", "captcha"),
    ("Lihat/ganti akun tersimpan", "credlist"),
    ("Tambah akun baru (butuh WhatsApp)", "generate"),
    ("Credits Pembuat Tools", "credits"),
]


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return "0"


def interactive() -> int:
    while True:
        print(BANNER)
        store = load_store() if CRED_FILE.exists() else {}
        active = store.get("active") or "Belum ada"
        print(f"Status Akun Aktif: {active}\n")
        print("Pilih fitur:")
        for i, (label, _) in enumerate(MENU, 1):
            print(f"  {i}. {label}")
        print("  0. Keluar\n")
        
        choice = ask("Nomor pilihan: ")
        if choice in ("0", "q", "keluar", ""):
            print("Keluar...")
            return 0
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(MENU)):
                print("Pilihan tidak valid.\n")
                continue
        except ValueError:
            print("Masukkan angka.\n")
            continue

        action = MENU[idx][1]
        try:
            if action == "credits":
                print("\n" + "=" * 40)
                print("         CREDITS PEMBUAT TOOLS")
                print("=" * 40)
                print("  • RendiSec")
                print("  • VynnGrup")
                print("  • PutraWibu")
                print("  • GeminiAi")
                print("  • XynnHd")
                print("  • Xynaa")
                print("=" * 40)
            elif action == "profile":
                menu_search("profile")
            elif action == "tags":
                menu_search("tags")
            elif action == "quota":
                menu_quota()
            elif action == "batch":
                menu_batch()
            elif action == "captcha":
                menu_captcha()
            elif action == "credlist":
                menu_cred_list()
            elif action == "generate":
                menu_generate()
                
            input("\nTekan Enter untuk kembali ke menu... ")
            print("\n" * 2)
        except GtcError as e:
            print(f"\n[Error] {e}")
            input("\nTekan Enter untuk kembali ke menu... ")
            print("\n" * 2)
        except Exception as e:
            print(f"\n[Unexpected Error] {e}")
            input("\nTekan Enter untuk kembali ke menu... ")
            print("\n" * 2)


def main() -> int:
    return interactive()


if __name__ == "__main__":
    sys.exit(main())
