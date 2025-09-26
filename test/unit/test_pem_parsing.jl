# test_cose_keys_native_pem.jl
using Test, WebAuthn

@testset "asn1_parse_length short/long form" begin
    # Short-form
    b = UInt8[0x02, 0x01, 0x41]
    len, off = WebAuthn.asn1_parse_length(b, 2)
    @test len == 1
    @test off == 3

    # Long-form: 2-byte
    b2 = UInt8[0x02, 0x82, 0x01, 0x00]
    len, off = WebAuthn.asn1_parse_length(b2, 2)
    @test len == 256
    @test off == 5

    # Long-form: 3-byte
    b3 = UInt8[0x02, 0x83, 0x01, 0x01, 0x01]
    len, off = WebAuthn.asn1_parse_length(b3, 2)
    @test len == 0x010101
    @test off == 6

    # Error: Run out of bytes
    b4 = UInt8[0x02, 0x83, 0x01]
    @test_throws BoundsError WebAuthn.asn1_parse_length(b4, 2)
end

@testset "find_bitstring utility" begin
    # EC-style: Bit string, unused bits=0, 0x04 prefix, len=66
    der = vcat(UInt8[0x03, 0x42, 0x00, 0x04], rand(UInt8, 65))
    idx, bitlen, unusedbits, content_off = WebAuthn.find_bitstring(der;
        require_uncompressed=true, required_len=66)
    @test idx == 1
    @test bitlen == 0x42
    @test unusedbits == 0x00
    @test der[content_off] == 0x04

    # No suitable bit string
    bad_der = UInt8[0x03, 0x42, 0x00, 0x05]  # not uncompressed (0x04)
    @test_throws ErrorException WebAuthn.find_bitstring(bad_der;
        require_uncompressed=true, required_len=66)
end

@testset "pem_to_der utility" begin
    # Good PEM
    pem = "-----BEGIN PUBLIC KEY-----\nQUJDRA==\n-----END PUBLIC KEY-----"
    der = WebAuthn.pem_to_der(pem)
    @test der == UInt8['A', 'B', 'C', 'D']

    # Bad PEM: bad header/footer
    badpem = "NOPE"
    @test_throws ErrorException WebAuthn.pem_to_der(badpem)
end

# Der↔PEM round‐trip
@testset "der_to_pem / pem_to_der roundtrip" begin
    # pick a small arbitrary DER blob:
    der = UInt8[0x30, 0x03, 0x02, 0x01, 0x05]  # DER for INTEGER(5)
    pem = WebAuthn.der_to_pem(der, "INTEGER")
    @test occursin("-----BEGIN INTEGER-----", pem)
    @test occursin("-----END INTEGER-----", pem)
    der2 = WebAuthn.pem_to_der(pem)
    @test der2 == der
end

# extract_pubkey_pem_from_der + extract_pubkey_from_der_raw
@testset "extract_pubkey_pem_from_der & extract_pubkey_from_der_raw" begin
    # Let's take the same SPKI prefix + uncompressed P-256 point used elsewhere:
    spki_prefix = UInt8[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
        0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    ]
    # sample 65‐byte uncompressed point:
    pubpoint = UInt8[0x04; rand(UInt8, 64)]
    der = vcat(spki_prefix, pubpoint)

    # 1) extract as PEM
    pem = WebAuthn.extract_pubkey_pem_from_der(der)
    @test occursin("BEGIN PUBLIC KEY", pem)

    # 2) extract_pubkey_from_der_raw → EC2PublicKey
    key = WebAuthn.extract_pubkey_from_der_raw(der)
    @test key isa WebAuthn.EC2PublicKey
    @test key.x == pubpoint[2:33]
    @test key.y == pubpoint[34:65]
end

# parse_assertion
@testset "parse_assertion" begin
    ad = UInt8[1, 2, 3, 4, 5]
    sig = UInt8[0xAA, 0xBB, 0xCC]
    b64_ad = WebAuthn.base64urlencode(ad)
    b64_sig = WebAuthn.base64urlencode(sig)
    ad2, sig2 = WebAuthn.parse_assertion(b64_ad, b64_sig)
    @test ad2 == ad
    @test sig2 == sig
end

@testset "parse_ec_pem_xy: Extract EC P-256 coordinates" begin
    p256_pem = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK4CWBHImRgAVPXrmUD7VhNFW1sUs
    GI17tvaN6KEkBukdOj8cXnZSnhFuPrf8ajP8KrRoYiZqHVFy8zyrPJzFnw==
    -----END PUBLIC KEY-----
    """
    p256_x_hex = "2b80960472264600153d7ae6503ed584d156d6c52c188d7bb6f68de8a124\
    06e9"
    p256_y_hex = "1d3a3f1c5e76529e116e3eb7fc6a33fc2ab46862266a1d5172f33cab3c9c\
    c59f"
    x, y = parse_ec_pem_xy(p256_pem)
    @test lowercase(bytes2hex(x)) == p256_x_hex
    @test lowercase(bytes2hex(y)) == p256_y_hex
    @test length(x) == 32
    @test length(y) == 32
end

@testset "parse_rsa_pem_ne: Extract RSA modulus/exponent" begin
    rsa_pem = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2auHrQvvpQv/DI1wQAmd
    YCUYzOr8hWU2rMtDEae/p5Cu5pyNJRdv7DjOdOeWeWq1rA/Od/GY/HYazst1lWMC
    XjiW3nf0yV1jHoXl9Dc1wFTxl7EKrykK2EsijB8f93f4scxEalIyfjauXC6hIPi4
    /yWGS8cJOuj35ac/7N6GrUMIdzCj0qumTrUhRkmsJo2HtGm3dKkEZxHnL7fs/hln
    wwVOl2rqH0EcaVBSZwvjuEt6EfVMhqINp9FhRaIq5gx0ZpBR6OpFPM5oXrtMgsKO
    vIdZK7yZPcKw0JLmymZMi5gjgGVTX48YHoM8Mi6KtB4k2Rbp3Ouqc56odpLx2K2S
    cwIDAQAB
    -----END PUBLIC KEY-----
    """
    n, e = parse_rsa_pem_ne(rsa_pem)
    n_hex = lowercase(bytes2hex(n))
    e_hex = lowercase(bytes2hex(e))
    @test e_hex == "010001"      # common for all major RSA keys
    @test length(e) in (3, 4)
    @test length(n) > 200         # 2048-bit modulus (256 bytes)
end

@testset "parse_ed25519_pem_x: Extract Ed25519 x coordinate" begin
    edpem = """
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEAoi3rnmJUD+qXNlp2pBkQWpXCUUjccW+6Ue5r0QDPF94=
    -----END PUBLIC KEY-----
    """
    ed_x_hex = "a22deb9e62540fea97365a76a419105a95c25148dc716fba51ee6bd100c\
    f17de"
    x = parse_ed25519_pem_x(edpem)
    @test lowercase(bytes2hex(x)) == ed_x_hex
    @test length(x) == 32
end

@testset "parse_ec_pem_xy: Bad input errors" begin
    # Not even PEM
    @test_throws Exception parse_ec_pem_xy("")
    # Not EC key PEM
    badpem = """
    -----BEGIN PUBLIC KEY-----
    MAAAABADBADBADBADBADB==
    -----END PUBLIC KEY-----
    """
    @test_throws Exception parse_ec_pem_xy(badpem)
end

@testset "parse_rsa_pem_ne: Bad input errors" begin
    @test_throws Exception parse_rsa_pem_ne("")
    @test_throws Exception parse_rsa_pem_ne(edpem)  # actually an Ed25519 key
end

@testset "parse_ed25519_pem_x: Bad input errors" begin
    @test_throws Exception parse_ed25519_pem_x("")
    @test_throws Exception parse_ed25519_pem_x(rsa_pem)
end

@testset "verify_webauthn_signature(PEM::String) fallback for Ed25519" begin
    # generate an Ed25519 keypair
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0

    # make a COSE OKP struct and convert to PEM
    cose = Dict(1 => 1, 3 => -8, -1 => 6, -2 => pk)
    key = WebAuthn.cose_key_parse(cose)
    pem = WebAuthn.cose_key_to_pem(key)

    # random authenticatorData + clientDataJSON
    ad = rand(UInt8, 37)
    cdj = rand(UInt8, 32)
    msg = vcat(ad, SHA.sha256(cdj))

    # sign via Sodium
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk) == 0

    # now verify via String‐PEM dispatch
    ok = verify_webauthn_signature(pem, ad, cdj, sig)
    @test ok

    # flip a byte → should fail
    sig2 = copy(sig)
    sig2[1] ⊻= 0xFF
    @test !verify_webauthn_signature(pem, ad, cdj, sig2)
end