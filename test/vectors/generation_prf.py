#!/usr/bin/env python3

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import cbor2
import hashlib

# --- Deterministic PRNG from a seed (SHA256) ---
def prng(seed: bytes, idx: int) -> bytes:
    return hashlib.sha256(seed + idx.to_bytes(1, 'big')).digest()

def hkdf_sha256(salt, ikm, length, info):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)

def aes256cbc_enc(key: bytes, data: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()

def aes256cbc_dec(key: bytes, ct: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

class PinProtocolV1:
    def ecdh(self, priv, peer_pub):
        shared = priv.exchange(ec.ECDH(), peer_pub)
        return hashlib.sha256(shared).digest()

    def encrypt(self, key, plaintext, iv=None):
        if iv is None:
            iv = b"\x00" * 16
        return aes256cbc_enc(key, plaintext, iv)

    def decrypt(self, key, ciphertext, iv=None):
        if iv is None:
            iv = b"\x00" * 16
        return aes256cbc_dec(key, ciphertext, iv)

    def get_shared_secret(self, priv, peer_pub):
        return self.ecdh(priv, peer_pub)

class PinProtocolV2(PinProtocolV1):
    def kdf(self, Z):
        hmac_key = hkdf_sha256(b"\x00"*32, Z, 32, b"CTAP2 HMAC key")
        aes_key  = hkdf_sha256(b"\x00"*32, Z, 32, b"CTAP2 AES key")
        return hmac_key + aes_key

    def ecdh(self, priv, peer_pub):
        shared = priv.exchange(ec.ECDH(), peer_pub)
        return self.kdf(shared)

    def encrypt(self, key, plaintext, iv=None):
        if iv is None:
            raise Exception("IV required for PIN2")
        aes_key = key[32:]
        return iv + aes256cbc_enc(aes_key, plaintext, iv)

    def decrypt(self, key, ciphertext, iv=None):
        aes_key = key[32:]
        iv = ciphertext[:16]
        body = ciphertext[16:]
        out = aes256cbc_dec(aes_key, body, iv)
        return out

def deterministic_edcsa_keys(seed: bytes):
    priv_ec = ec.derive_private_key(int.from_bytes(seed, "big"), ec.SECP256R1())
    return priv_ec, priv_ec.public_key()

def make_vector(
    outdir, 
    proto,  # PinProtocolV1 or PinProtocolV2
    cred_random: bytes,
    plat_priv: ec.EllipticCurvePrivateKey,
    auth_priv: ec.EllipticCurvePrivateKey,
    prf_challenge_1: bytes,
    prf_challenge_2: bytes or None,
    iv_salt: bytes or None,
    iv_output: bytes or None
):
    # 1. Shared ECDH
    shared = proto.ecdh(auth_priv, plat_priv.public_key())
    # 2. Compute salts (per spec)
    salt1 = hashlib.sha256(b"WebAuthn PRF" + b"\x00" + prf_challenge_1).digest()
    salt2 = None
    if prf_challenge_2 is not None:
        salt2 = hashlib.sha256(b"WebAuthn PRF" + b"\x00" + prf_challenge_2).digest()
    # 3. Salt input for extension (CBOR)
    salt_plain = salt1 + (salt2 if salt2 else b"")
    salt_enc = proto.encrypt(shared, salt_plain, iv_salt)
    ext_input  = {"hmac-secret": salt_enc}
    # 4. Authenticator output: HMAC(cred_random, salt1/salt2)
    h = hmac.HMAC(cred_random, hashes.SHA256())
    h.update(salt1)
    out1 = h.finalize()
    if salt2:
        h = hmac.HMAC(cred_random, hashes.SHA256())
        h.update(salt2)
        out2 = h.finalize()
    else:
        out2 = b""
    # 5. Output enc
    out_plain = out1 + out2
    if iv_output is not None:
        output_enc = proto.encrypt(shared, out_plain, iv_output)
    else:
        output_enc = proto.encrypt(shared, out_plain)
    ext_output = {"hmac-secret": output_enc}
    # 6. Write
    Path(outdir).mkdir(parents=True, exist_ok=True)
    with open(f"{outdir}/input.cbor", "wb") as f:
        f.write(cbor2.dumps(ext_input))
    with open(f"{outdir}/output.cbor", "wb") as f:
        f.write(cbor2.dumps(ext_output))
    print(f"→ {outdir}: input.cbor, output.cbor")

def main():
    base = Path("vectors_prf_ctap")
    # Deterministic seed for all steps
    seed = b"WebAuthn PRF test vectors"
    # Deterministically derive keys and challenges
    cred_random = prng(seed, 2)   # Secret for PRF
    plat_seed = prng(seed, 3)
    auth_seed = prng(seed, 4)
    plat_priv, plat_pub = deterministic_edcsa_keys(plat_seed)
    auth_priv, auth_pub = deterministic_edcsa_keys(auth_seed)
    # pin protocols
    pp1 = PinProtocolV1()
    pp2 = PinProtocolV2()

    # --- Single input PIN2
    make_vector(
        base/"single-pp2",
        pp2,
        cred_random,
        plat_priv,
        auth_priv,
        prf_challenge_1=seed + b"PIN2a", prf_challenge_2=None,
        iv_salt=prng(seed, 10)[:16],
        iv_output=prng(seed, 20)[:16]
    )
    # --- Two input PIN2
    make_vector(
        base/"two-pp2",
        pp2,
        cred_random,
        plat_priv,
        auth_priv,
        prf_challenge_1=seed + b"PIN2b",
        prf_challenge_2=seed + b"PIN2c",
        iv_salt=prng(seed, 11)[:16],
        iv_output=prng(seed, 21)[:16]
    )
    # --- Single input PIN1
    make_vector(
        base/"single-pp1",
        pp1,
        cred_random,
        plat_priv,
        auth_priv,
        prf_challenge_1=seed + b"PIN1",
        prf_challenge_2=None,
        iv_salt=None,
        iv_output=None
    )

if __name__ == "__main__":
    main()