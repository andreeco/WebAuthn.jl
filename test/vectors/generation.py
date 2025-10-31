#!/usr/bin/env python3

# python3 -m venv webauthn-env
# source webauthn-env/bin/activate

# pip install --upgrade pip
# pip install cryptography cbor2 fido2
#  grep -r 'load_vector' .

#!/usr/bin/env python3

import os, base64, struct, json, datetime
from pathlib import Path
import cbor2

from cryptography.hazmat.primitives.asymmetric import (
    ec, rsa, ed25519
)
from cryptography.hazmat.primitives.asymmetric import padding as RSAPadding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from fido2.utils import sha256
from fido2.webauthn import (
    AttestationObject, AuthenticatorData, AttestedCredentialData
)

try:
    from cryptography.hazmat.primitives.asymmetric import ed448
    HAVE_ED448 = True
except ImportError:
    HAVE_ED448 = False

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def wr(f, b: bytes): f.write_bytes(b)

def gen_client_data(challenge: bytes, tp: str) -> bytes:
    return json.dumps({
        "type":tp,
        "challenge":b64url(challenge),
        "origin":"https://example.org"
    },separators=(",",":")).encode()

def now():
    return datetime.datetime(2024,1,1,tzinfo=datetime.timezone.utc)
def distant_future():
    return datetime.datetime(3024,1,1,tzinfo=datetime.timezone.utc)

def save_keypair(path, priv):
    pub = priv.public_key()
    wr(path / "privkey.pem", priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ))
    wr(path / "pubkey.pem", pub.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ))
    wr(path / "pubkey.der", pub.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    ))

def make_cose_ec2(pub):
    pub_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return {1:2, 3:-7, -1:1, -2:pub_bytes[1:33], -3:pub_bytes[33:65]}

def make_cose_p384(pub):
    pub_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return {1:2,3:-35,-1:2,-2:pub_bytes[1:49],-3:pub_bytes[49:97]}

def make_cose_p521(pub):
    pub_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return {1:2,3:-36,-1:3,-2:pub_bytes[1:67],-3:pub_bytes[67:133]}

def make_cose_rsa(pub):
    n = pub.public_numbers().n
    e = pub.public_numbers().e
    return {1:3, 3:-257, -1:n.to_bytes((n.bit_length()+7)//8,'big'),-2:e.to_bytes((e.bit_length()+7)//8,'big')}

def make_cose_okp(pub):
    x = pub.public_bytes(Encoding.Raw,PublicFormat.Raw)
    return {1:1,3:-8,-1:6,-2:x}

def make_cose_ed448(pub):
    x = pub.public_bytes(Encoding.Raw,PublicFormat.Raw)
    return {1:1,3:-9,-1:7,-2:x}

def ensure_dir(d): Path(d).mkdir(parents=True, exist_ok=True)

def mk_credid(): return os.urandom(32)
def mk_aaguid(): return os.urandom(16)
def mk_challenge(): return os.urandom(32)
def mk_cbor(f, x): wr(f, cbor2.dumps(x))

def gen_x509_ca():
    priv = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,"Test CA Org")])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(priv.public_key())\
        .serial_number(int.from_bytes(os.urandom(16),'big'))\
        .not_valid_before(now())\
        .not_valid_after(distant_future())\
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),True)\
        .sign(priv,hashes.SHA256())
    return cert, priv

def gen_x509_apple_leaf(ca_cert, ca_priv, pubkey):
    nonce = os.urandom(32)
    ext = x509.UnrecognizedExtension(ObjectIdentifier("1.2.840.113635.100.8.2"), nonce)
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,"AppleWebAuthnOrg")])
    cert = x509.CertificateBuilder()\
        .subject_name(subject).issuer_name(ca_cert.subject)\
        .public_key(pubkey)\
        .serial_number(int.from_bytes(os.urandom(16),'big'))\
        .not_valid_before(now())\
        .not_valid_after(distant_future())\
        .add_extension(ext, False)\
        .sign(ca_priv, hashes.SHA256())
    return cert, nonce

def gen_x509_android_leaf(ca_cert, ca_priv, pubkey):
    auth_chal = os.urandom(32)
    ext = x509.UnrecognizedExtension(ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), auth_chal)
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,"AndroidWebAuthnOrg")])
    cert = x509.CertificateBuilder()\
        .subject_name(subject).issuer_name(ca_cert.subject)\
        .public_key(pubkey)\
        .serial_number(int.from_bytes(os.urandom(16),'big'))\
        .not_valid_before(now())\
        .not_valid_after(distant_future())\
        .add_extension(ext, False)\
        .sign(ca_priv, hashes.SHA256())
    return cert, auth_chal

def gen_x509_tpm_leaf(ca_cert, ca_priv, pubkey):
    ext = x509.UnrecognizedExtension(ObjectIdentifier("2.23.133.8.3"), b"tpm attestation test ext")
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,"TPMWebAuthnOrg")])
    cert = x509.CertificateBuilder()\
        .subject_name(subject).issuer_name(ca_cert.subject)\
        .public_key(pubkey)\
        .serial_number(int.from_bytes(os.urandom(16),'big'))\
        .not_valid_before(now())\
        .not_valid_after(distant_future())\
        .add_extension(ext, False)\
        .sign(ca_priv, hashes.SHA256())
    return cert

def _make_dirs(base):
    ensure_dir(base)
    ensure_dir(base/"registration")
    ensure_dir(base/"authentication")

def register_and_assertion(
    dirname, privkey, cosefn, fmt="none", ca=None, ca_priv=None, extdata=None, alg_override=None, packed_self=False
):
    base = Path(dirname)
    _make_dirs(base)
    save_keypair(base, privkey)
    challenge = mk_challenge()
    aaguid = mk_aaguid()
    credid = mk_credid()
    # Client data
    client_data_reg = gen_client_data(challenge, "webauthn.create")
    wr(base/"registration"/"clientDataJSON.bin", client_data_reg)
    client_data_auth = gen_client_data(challenge, "webauthn.get")
    wr(base/"authentication"/"clientDataJSON.bin", client_data_auth)
    # Flat for some tests
    wr(base/"clientDataJSON.bin", client_data_reg)
    wr(base/"assertion_clientDataJSON.bin", client_data_auth)
    ckey = cosefn(privkey.public_key())
    mk_cbor(base/"cose_key.cbor", ckey)
    attcred = AttestedCredentialData.create(aaguid, credid, ckey)
    rpidhash = sha256(b"example.org")
    flags = 0x41
    signcount = 1
    authdata = AuthenticatorData.create(
        rp_id_hash=rpidhash,
        flags=flags,
        counter=signcount,
        credential_data=bytes(attcred),
        extensions=None
    )
    wr(base/"registration"/"authenticatorData.bin", bytes(authdata))
    wr(base/"authenticatorData.bin", bytes(authdata))

    att_stmt = {} ; sig = b""
    if fmt == "none":
        pass
    elif fmt in ("packed", "packed-self"):
        msg = bytes(authdata) + sha256(client_data_reg)
        key_to_sign = privkey if packed_self else privkey
        if isinstance(privkey, ec.EllipticCurvePrivateKey):
            sig = privkey.sign(msg, ec.ECDSA(hashes.SHA256()))
            alg = -7 if alg_override is None else alg_override
        elif isinstance(privkey, rsa.RSAPrivateKey):
            sig = privkey.sign(msg, RSAPadding.PKCS1v15(), hashes.SHA256())
            alg = -257
        elif HAVE_ED448 and isinstance(privkey, ed448.Ed448PrivateKey):
            sig = privkey.sign(msg)
            alg = -9
        elif isinstance(privkey, ed25519.Ed25519PrivateKey):
            sig = privkey.sign(msg)
            alg = -8
        else:
            raise Exception("Unknown key type")
        att_stmt = {"alg": alg, "sig": sig}
    elif fmt == "apple":
        leafcert, nonce = gen_x509_apple_leaf(ca, ca_priv, privkey.public_key())
        att_stmt = {"fmt":"apple", "x5c":[leafcert.public_bytes(Encoding.DER)], "nonce": nonce}
    elif fmt == "android-key":
        leafcert, achal = gen_x509_android_leaf(ca, ca_priv, privkey.public_key())
        att_stmt = {"fmt":"android-key", "x5c":[leafcert.public_bytes(Encoding.DER)], "challenge": achal}
    elif fmt == "tpm":
        leafcert = gen_x509_tpm_leaf(ca, ca_priv, privkey.public_key())
        fake_certinfo = b"certinfo_tpm123"
        fake_pubarea = b"pubarea_tpm123"
        att_stmt = {"fmt":"tpm", "x5c":[leafcert.public_bytes(Encoding.DER)], "certInfo": fake_certinfo, "pubArea": fake_pubarea}
    elif fmt == "fido-u2f":
        leafcert, _= gen_x509_apple_leaf(ca, ca_priv, privkey.public_key())
        msg = bytes([0]) + rpidhash + sha256(client_data_reg) + credid + privkey.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        sig = privkey.sign(msg, ec.ECDSA(hashes.SHA256())) if isinstance(privkey, ec.EllipticCurvePrivateKey) else privkey.sign(msg)
        att_stmt = {"fmt":"fido-u2f", "x5c":[leafcert.public_bytes(Encoding.DER)], "sig": sig}
    else:
        raise Exception("Unknown attestation fmt")

    myfmt = fmt if fmt not in ["apple", "android-key", "tpm", "fido-u2f"] else att_stmt["fmt"]
    attobj = AttestationObject.create(
        myfmt,
        bytes(authdata),
        att_stmt if fmt != "none" else {}
    )
    wr(base/"registration"/"attestationObject.cbor", bytes(attobj))

    msg_auth = bytes(authdata) + sha256(client_data_auth)
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        sig_auth = privkey.sign(msg_auth, ec.ECDSA(hashes.SHA256()))
    elif isinstance(privkey, rsa.RSAPrivateKey):
        sig_auth = privkey.sign(msg_auth, RSAPadding.PKCS1v15(), hashes.SHA256())
    elif HAVE_ED448 and isinstance(privkey, ed448.Ed448PrivateKey):
        sig_auth = privkey.sign(msg_auth)
    elif isinstance(privkey, ed25519.Ed25519PrivateKey):
        sig_auth = privkey.sign(msg_auth)
    else:
        sig_auth = b""
    wr(base/"authentication"/"authenticatorData.bin", bytes(authdata))
    wr(base/"authentication"/"signature.bin", sig_auth)
    wr(base/"authentication"/"clientDataJSON.bin", client_data_auth)

def generate_der_structure_vectors():
    """Generate canonical and edgy ASN.1/DER structure files for test parsers."""
    outdir = Path("keys")
    outdir.mkdir(exist_ok=True, parents=True)
    with open(outdir/"int_42.der", "wb") as f:
        f.write(b"\x02\x01\x2a")
    with open(outdir/"int_42_overlong.der", "wb") as f:
        f.write(b"\x02\x02\x00\x2a")
    with open(outdir/"null.der", "wb") as f:
        f.write(b"\x05\x00")
    with open(outdir/"bool_true.der", "wb") as f:
        f.write(b"\x01\x01\xff")
    with open(outdir/"oid_rsaEncryption.der", "wb") as f:
        f.write(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
    with open(outdir/"bitstring.der", "wb") as f:
        f.write(b"\x03\x02\x00\xd3")
    with open(outdir/"bitstring_badunused.der", "wb") as f:
        f.write(b"\x03\x02\x09\x00")
    with open(outdir/"octetstring.der", "wb") as f:
        f.write(b"\x04\x04\xde\xad\xbe\xef")
    with open(outdir/"octetstring_indef.der", "wb") as f:
        f.write(b"\x04\x80\xde\xad\xbe\xef\x00\x00")
    with open(outdir/"string.der", "wb") as f:
        f.write(b"\x13\x0aHelloJULIA")
    with open(outdir/"sequence.der", "wb") as f:
        f.write(b"\x30\x06\x02\x01\x01\x02\x01\x02")
    # DER-canonical SET: {1, 2}
    with open(outdir/"set.der", "wb") as f:
     f.write(b"\x31\x06\x02\x01\x01\x02\x01\x02")
    # Non-canonical BER style SET: {2, 1}
    with open(outdir/"set_outoforder.der", "wb") as f:
     f.write(b"\x31\x06\x02\x01\x02\x02\x01\x01")
    with open(outdir/"nested.der", "wb") as f:
        f.write(b"\x30\x08\x30\x06\x02\x01\x01\x02\x01\x02")
    print("✓ ASN.1/DER structure files re-generated in keys/")

def generate_x509_der_vectors():
    """
    Write deterministic X.509 CA, EE, and RSA CA test certs (DER+PEM)
    to keys/ for test parsing.
    """
    outdir = Path("keys")
    outdir.mkdir(exist_ok=True, parents=True)

    # EC P-256 CA
    ca_priv = ec.derive_private_key(0xDEADBEEF, ec.SECP256R1())
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test CA Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"EC-P256 Test CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_priv.public_key())
        .serial_number(999)
        .not_valid_before(datetime.datetime(2020,1,1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2031,1,1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_priv, hashes.SHA256(), default_backend())
    )
    (outdir/"x509_ca.der").write_bytes(ca_cert.public_bytes(Encoding.DER))
    (outdir/"x509_ca.pem").write_bytes(ca_cert.public_bytes(Encoding.PEM))

    # EC EE (subordinate, signed by CA)
    ee_priv = ec.derive_private_key(0xBEEFEED, ec.SECP256R1())
    ee_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test EE Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"EC-P256 Test EE"),
    ])
    ee_cert = (
        x509.CertificateBuilder()
        .subject_name(ee_subject)
        .issuer_name(ca_subject)
        .public_key(ee_priv.public_key())
        .serial_number(888)
        .not_valid_before(datetime.datetime(2023,1,1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2035,1,1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_priv, hashes.SHA256(), default_backend())
    )
    (outdir/"x509_ee.der").write_bytes(ee_cert.public_bytes(Encoding.DER))
    (outdir/"x509_ee.pem").write_bytes(ee_cert.public_bytes(Encoding.PEM))

    rsa_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    rsa_subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test RSA CA Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"RSA-Test-CA"),
    ])
    rsa_cert = (
        x509.CertificateBuilder()
        .subject_name(rsa_subject)
        .issuer_name(rsa_subject)
        .public_key(rsa_priv.public_key())
        .serial_number(42)
        .not_valid_before(datetime.datetime(2022,1,1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2040,1,1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(rsa_priv, hashes.SHA256(), default_backend())
    )
    (outdir/"x509_rsa.der").write_bytes(rsa_cert.public_bytes(Encoding.DER))
    (outdir/"x509_rsa.pem").write_bytes(rsa_cert.public_bytes(Encoding.PEM))
    print("✓ Deterministic X.509 CA/EE/RSA test certs regenerated in keys/")

def generate_spki_vectors():
    """Generate SPKI/PEM/DER test assets in keys for ASN.1 OpenSSL cross-tests."""
    outdir = Path("keys")
    outdir.mkdir(exist_ok=True, parents=True)

    # EC P-256 test SPKI PEM/DER
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()
    ec_spki_pem = ec_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    ec_spki_der = ec_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    (outdir/"ec_p256_spki.pem").write_bytes(ec_spki_pem)
    (outdir/"ec_p256_spki.der").write_bytes(ec_spki_der)

    # RSA test SPKI PEM/DER
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()
    rsa_spki_pem = rsa_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    rsa_spki_der = rsa_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    (outdir/"rsa_spki.pem").write_bytes(rsa_spki_pem)
    (outdir/"rsa_spki.der").write_bytes(rsa_spki_der)

    # Ed25519 test SPKI PEM/DER
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ed_spki_pem = ed_pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    ed_spki_der = ed_pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    (outdir/"ed25519_spki.pem").write_bytes(ed_spki_pem)
    (outdir/"ed25519_spki.der").write_bytes(ed_spki_der)

    print("SPKI test pubkey files generated.")

def generate_rsa_raw_der():
    """
    Write deterministic raw RSAPublicKey DER to keys/ for low-level ASN.1 tests.
    """
    outdir = Path("keys")
    outdir.mkdir(exist_ok=True, parents=True)
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()
    n = rsa_pub.public_numbers().n
    e = rsa_pub.public_numbers().e

    def der_length(length):
        if length < 0x80:
            return bytes([length])
        else:
            llen = (length.bit_length() + 7) // 8
            return bytes([0x80 | llen]) + length.to_bytes(llen, "big")

    def asn1_int(val):
        intval = val.to_bytes((val.bit_length()+7)//8, 'big')
        if len(intval) == 0:
            intval = b"\x00"
        if intval[0] & 0x80:
            intval = b"\x00" + intval
        return b"\x02" + der_length(len(intval)) + intval

    body = asn1_int(n) + asn1_int(e)
    der = b"\x30" + der_length(len(body)) + body
    (outdir/"rsa_raw.der").write_bytes(der)
    print("✓ rsa_raw.der written (raw RSA public key, DER SEQUENCE) in keys/")
    
def main():
    ca, ca_priv = gen_x509_ca()

    # EC2/P-256: None/pure packed/packed-self
    register_and_assertion("vectors_ec2_none", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="none")
    register_and_assertion("vectors_ec2_packed", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="packed")
    register_and_assertion("vectors_ec2_packed_self", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="packed-self", packed_self=True)

    # P-384, P-521
    register_and_assertion("vectors_ec2_p384_packed", ec.generate_private_key(ec.SECP384R1()), make_cose_p384, fmt="packed", alg_override=-35)
    register_and_assertion("vectors_ec2_p521_packed", ec.generate_private_key(ec.SECP521R1()), make_cose_p521, fmt="packed", alg_override=-36)

    # RSA
    register_and_assertion("vectors_rsa_packed", rsa.generate_private_key(public_exponent=65537,key_size=2048), make_cose_rsa, fmt="packed")

    # Ed25519
    register_and_assertion("vectors_ed25519_packed", ed25519.Ed25519PrivateKey.generate(), make_cose_okp, fmt="packed")

    # Ed448 (if available)
    if HAVE_ED448:
        register_and_assertion("vectors_ed448_packed", ed448.Ed448PrivateKey.generate(), make_cose_ed448, fmt="packed")

    # Special formats
    register_and_assertion("vectors_apple", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="apple", ca=ca, ca_priv=ca_priv)
    register_and_assertion("vectors_android", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="android-key", ca=ca, ca_priv=ca_priv)
    register_and_assertion("vectors_tpm", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="tpm", ca=ca, ca_priv=ca_priv)
    register_and_assertion("vectors_fidou2f", ec.generate_private_key(ec.SECP256R1()), make_cose_ec2, fmt="fido-u2f", ca=ca, ca_priv=ca_priv)
    generate_der_structure_vectors()
    generate_x509_der_vectors()
    generate_spki_vectors()
    generate_rsa_raw_der()
    print("Test vectors generated.")

if __name__ == "__main__":
    main()