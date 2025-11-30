import json
import os
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

REGISTRY = "key_versions.json"
DATA_DIR = "data"
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
WRAPPED_FILE = "wrapped_data_key.bin"

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def _load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def _load_registry():
    if not os.path.exists(REGISTRY):
        return {"current_version": None, "versions": {}}
    return _load_json(REGISTRY)

def _save_registry(reg):
    _save_json(REGISTRY, reg)

def _get_current_fernet(reg=None):
    reg = reg or _load_registry()
    v = reg.get("current_version")
    if not v:
        raise RuntimeError("No data key found. Run: python main.py gen-keys")
    key_b64 = reg["versions"][v]["key"]
    return Fernet(key_b64.encode())

def generate_keys():
    # RSA pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    # Symmetric data key (Fernet/AES128-CBC+HMAC)
    data_key = Fernet.generate_key().decode()
    reg = {
        "current_version": "v1",
        "versions": {
            "v1": {
                "key": data_key,
                "created_at": _now_iso(),
                "retired_at": None,
            }
        },
    }
    _save_registry(reg)

    # Seed a sample plaintext
    _ensure_data_dir()
    if not os.path.exists(os.path.join(DATA_DIR, "plain.txt")):
        with open(os.path.join(DATA_DIR, "plain.txt"), "w") as f:
            f.write("Hello, Lab 2! This file will be encrypted.\n")

    print("[OK] Generated RSA key pair, created data key v1, and scaffolded sample data.")

def encrypt_file(infile, outfile):
    reg = _load_registry()
    fernet = _get_current_fernet(reg)
    with open(infile, "rb") as f:
        pt = f.read()
    ct = fernet.encrypt(pt)
    with open(outfile, "wb") as f:
        f.write(ct)
    print(f"[OK] Encrypted {infile} -> {outfile} with {reg['current_version']}")

def decrypt_file(infile, outfile):
    reg = _load_registry()
    fernet = _get_current_fernet(reg)
    with open(infile, "rb") as f:
        ct = f.read()
    pt = fernet.decrypt(ct)
    with open(outfile, "wb") as f:
        f.write(pt)
    print(f"[OK] Decrypted {infile} -> {outfile} with {reg['current_version']}")

def wrap_data_key_with_rsa():
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise RuntimeError("Missing public key. Run gen-keys first.")
    reg = _load_registry()
    cur = reg["current_version"]
    key_b64 = reg["versions"][cur]["key"]

    with open(PUBLIC_KEY_FILE, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

    wrapped = pub.encrypt(
        base64.urlsafe_b64decode(key_b64.encode()),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    with open(WRAPPED_FILE, "wb") as f:
        f.write(wrapped)
    print(f"[OK] Wrapped current data key ({cur}) to {WRAPPED_FILE} using RSA-OAEP.")

