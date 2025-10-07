# test_cose_keys_native_pem.jl

using Test, WebAuthn

# SPEC_ID: §5.8.5-COSEAlgorithmIdentifier
@testset "pem_to_der utility" begin
    # Minimal PEM to DER conversion
    pem = "-----BEGIN PUBLIC KEY-----\nQUJDRA==\n-----END PUBLIC KEY-----"
    der = WebAuthn.pem_to_der(pem)
    @test der == UInt8['A', 'B', 'C', 'D']
    # Bad input: should raise error
    badpem = "NOPE"
    @test_throws ErrorException WebAuthn.pem_to_der(badpem)
end

# SPEC_ID: §5.8.5-COSEAlgorithmIdentifier
@testset "der_to_pem / pem_to_der roundtrip" begin
    # DER for INTEGER(5)
    der = UInt8[0x30, 0x03, 0x02, 0x01, 0x05]
    pem = WebAuthn.der_to_pem(der, "INTEGER")
    @test occursin("-----BEGIN INTEGER-----", pem)
    @test occursin("-----END INTEGER-----", pem)
    der2 = WebAuthn.pem_to_der(pem)
    @test der2 == der
end

# SPEC_ID: §5.8.5-COSEAlgorithmIdentifier
# SPEC_ID: §3-COSE-EC2-crv-x-y-Length
@testset "extract_pubkey_pem_from_der & extract_pubkey_from_der_raw" begin
    # EC2 P-256 public key
    real_pem = raw"""
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9h4XuIKOJOLzI4JzMh/k4IAHSCbB
    eEYKabXd4dOCpYCTVIB98/Q5EibFH5HKzIO3oGKwJI5saxm7xYLVgnIPWA==
    -----END PUBLIC KEY-----
    """
    der = WebAuthn.pem_to_der(real_pem)
    @test isa(der, Vector{UInt8})
    pem = WebAuthn.extract_pubkey_pem_from_der(der)
    @test pem !== nothing && occursin("BEGIN PUBLIC KEY", pem)
    key = WebAuthn.extract_pubkey_from_der_raw(der)
    @test key isa WebAuthn.EC2PublicKey
    @test length(key.x) == 32
    @test length(key.y) == 32
end

# SPEC_ID: §5.2.2-AuthenticatorAssertionResponse
@testset "parse_assertion" begin
    ad = UInt8[1, 2, 3, 4, 5]
    sig = UInt8[0xAA, 0xBB, 0xCC]
    b64_ad = WebAuthn.base64urlencode(ad)
    b64_sig = WebAuthn.base64urlencode(sig)
    # SPEC_ID: §6.3.3-authenticatorGetAssertion
    ad2, sig2 = WebAuthn.parse_assertion(b64_ad, b64_sig)
    @test ad2 == ad
    @test sig2 == sig
end

# SPEC_ID: §3-COSE-EC2-crv-x-y-Length
@testset "parse_ec_pem_xy: Extract EC P-256 coordinates" begin
    p256_pem = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK4CWBHImRgAVPXrmUD7VhNFW1sUs
    GI17tvaN6KEkBukdOj8cXnZSnhFuPrf8ajP8KrRoYiZqHVFy8zyrPJzFnw==
    -----END PUBLIC KEY-----
    """
    p256_x_hex = "2b80960472264600153d7ae6503ed584d156d6c52c188d7bb6f68de8a12406e9"
    p256_y_hex = "1d3a3f1c5e76529e116e3eb7fc6a33fc2ab46862266a1d5172f33cab3c9cc59f"
    x, y = parse_ec_pem_xy(p256_pem)
    @test lowercase(bytes2hex(x)) == p256_x_hex
    @test lowercase(bytes2hex(y)) == p256_y_hex
    @test length(x) == 32
    @test length(y) == 32
end

# SPEC_ID: §3-COSE-RSAPublicKey-Fields
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
    @test e_hex == "010001"
    @test length(e) in (3, 4)
    @test length(n) > 200
end

# SPEC_ID: §3-COSE-OKP-Ed25519-crv-alg-x
@testset "parse_ed25519_pem_x: Extract Ed25519 x coordinate" begin
    edpem = """
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEAoi3rnmJUD+qXNlp2pBkQWpXCUUjccW+6Ue5r0QDPF94=
    -----END PUBLIC KEY-----
    """
    ed_x_hex = "a22deb9e62540fea97365a76a419105a95c25148dc716fba51ee6bd100cf17de"
    x = parse_ed25519_pem_x(edpem)
    @test lowercase(bytes2hex(x)) == ed_x_hex
    @test length(x) == 32
end

# SPEC_ID: §3-COSE-EC2-crv-x-y-Length
@testset "parse_ec_pem_xy: Bad input errors" begin
    @test_throws Exception parse_ec_pem_xy("")
    badpem = """
    -----BEGIN PUBLIC KEY-----
    MAAAABADBADBADBADBADB==
    -----END PUBLIC KEY-----
    """
    @test_throws Exception parse_ec_pem_xy(badpem)
end

# SPEC_ID: §3-COSE-RSAPublicKey-Fields
@testset "parse_rsa_pem_ne: Bad input errors" begin
    @test_throws Exception parse_rsa_pem_ne("")
    # Ed25519 is not RSA so must fail
    edpem = """
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEAoi3rnmJUD+qXNlp2pBkQWpXCUUjccW+6Ue5r0QDPF94=
    -----END PUBLIC KEY-----
    """
    @test_throws Exception parse_rsa_pem_ne(edpem)
end

# SPEC_ID: §3-COSE-OKP-Ed25519-crv-alg-x
@testset "parse_ed25519_pem_x: Bad input errors" begin
    @test_throws Exception parse_ed25519_pem_x("")
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
    @test_throws Exception parse_ed25519_pem_x(rsa_pem)
end

# SPEC_ID: §5.8.5-COSEAlgorithmIdentifier
# SPEC_ID: §3-COSE-OKP-Ed25519-crv-alg-x
@testset "verify_webauthn_signature(PEM::String) fallback for Ed25519" begin
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    # OKP struct/PEM conversion
    cose = Dict(1 => 1, 3 => -8, -1 => 6, -2 => pk)
    key = WebAuthn.cose_key_parse(cose)
    pem = WebAuthn.cose_key_to_pem(key)
    ad = rand(UInt8, 37)
    cdj = rand(UInt8, 32)
    msg = vcat(ad, SHA.sha256(cdj))
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk) == 0
    ok = verify_webauthn_signature(pem, ad, cdj, sig)
    @test ok
    sig2 = copy(sig)
    sig2[1] ⊻= 0xFF
    @test !verify_webauthn_signature(pem, ad, cdj, sig2)
end