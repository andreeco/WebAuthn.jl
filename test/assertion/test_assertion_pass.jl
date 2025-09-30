# test_assertion_pass.jl
# --------------------------------------------------
# Purpose: End-to-end assertion parsing and verification, 
# all supported key types.
# Spec: §5.2.2, §7.2
# Tests:
#   - Valid full browser-sourced assertions over stored credentials (pass)
#   - Each key type: EC2/P-256, RSA, Ed25519, etc.

using Test, WebAuthn, CBOR, SHA, Sodium, JSON3

@testset "Assertion/Authentication Happy Path: Ed25519/OKP" begin
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    cose = Dict(1 => 1, 3 => -8, -1 => 6, -2 => pk)
    key = cose_key_parse(CBOR.decode(CBOR.encode(cose)))
    @test isa(key, OKPPublicKey)
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
    authData = rand(UInt8, 37)
    clientDataJSON = rand(UInt8, 32)
    msg = vcat(authData, SHA.sha256(clientDataJSON))
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk) == 0
    @test Int(sl[]) == length(sig)
    @test verify_webauthn_signature(key, authData, clientDataJSON, sig)
    bad = copy(sig)
    bad[1] ⊻= 0xFF
    @test !verify_webauthn_signature(key, authData, clientDataJSON, bad)
end

@testset "Assertion/Authentication Happy Path: EC2/ES256 (fixed)" begin
    pem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7KH199o/ZEv7ECF+5Ny24FUKb6Rk
C82+y/BQk/Y32NTnlzVgVWpw75IxyiQuucw0QJbzN+zC8r2IIRek+HDPnA==
-----END PUBLIC KEY-----
"""
    authData = UInt8[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    clientDataJSON = UInt8[115, 111, 109, 101, 32, 119, 101, 98, 97, 117, 116,
        104, 110, 32, 109, 115, 103] # "some webauthn msg"
    sigDER = UInt8[
        48, 70, 2, 33, 0, 165, 112, 132, 109, 8, 170, 240, 227, 247, 195, 89,
        98, 241, 216, 133, 226, 70, 119, 221, 121, 98, 158, 162, 88, 55, 94,
        205, 50, 171, 231, 201, 26, 2, 33, 0, 213, 37, 123, 203, 127, 90, 173,
        85, 226, 130, 91, 186, 99, 254, 235, 235, 128, 196, 39, 181, 85, 222,
        101, 200, 95, 31, 239, 38, 171, 109, 128, 70
    ]

    verify_webauthn_signature(pem, authData, clientDataJSON, sigDER)

    @test verify_webauthn_signature(pem, authData, clientDataJSON, sigDER)
    badsig = copy(sigDER)
    badsig[10] ⊻= 0xFF
    @test !verify_webauthn_signature(pem, authData, clientDataJSON, badsig)
    badauth = copy(authData)
    badauth[1] = 0xFF
    @test !verify_webauthn_signature(pem, badauth, clientDataJSON, sigDER)
end

@testset "Assertion/Authentication Happy Path: RSA/RS256 (fixed)" begin
    pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkBTfOGiBZZmdgCPknh5Q
idkTn23OEiRdDVMzsoT7nd3ZWdkBVl0jdLsKPocHbB1V1O8JQFs7URScraQ0Huwq
mOxf5A2j4kL1gh9XQhzeK3yO3L+JdTWJaQyOYhn9Uw1dLblRt4AIWcKRBidsZmWk
q5x50rPXNSQUXjj0LaEXjJ+8wtiyn1B0FC9CnvlbJYo8klA8jwZVbg9Fvk5+ugs2
PGviXNa0A8Q0AfpZjjRGn/HptKDjMYxI0HBUA5Mc8g7IefQUlZ5KL1hMhSqBIMZ7
C/5ZO8gYJhMHRrdpdIHUqeDUE/C/rjnjItGRMZhxek6E3/qSA2O5JJ4w/OehHYCG
cwIDAQAB
-----END PUBLIC KEY-----
"""
    authData = UInt8[2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]
    # "webAuthn RSA"
    clientDataJSON = UInt8[119, 101, 98, 65, 117, 116, 104, 110, 32, 82, 83, 65]
    sig_der = UInt8[48, 5, 235, 115, 49, 15, 202, 248, 244, 151, 113, 26, 2,
        97, 44, 182, 209, 91, 236, 138, 68, 89, 90, 5, 6, 2, 199, 83, 110, 54,
        18, 81, 190, 227, 167, 234, 213, 33, 232, 245, 50, 243, 208, 78, 236,
        131, 23, 135, 147, 234, 71, 160, 166, 133, 81, 113, 229, 30, 46, 172,
        135, 161, 46, 26, 58, 223, 156, 131, 11, 196, 5, 191, 132, 176, 78, 219,
        89, 190, 77, 117, 94, 2, 75, 201, 111, 24, 250, 191, 221, 39, 26, 138,
        26, 203, 36, 186, 253, 30, 37, 33, 167, 234, 107, 32, 52, 180, 241, 236,
        244, 135, 108, 229, 63, 42, 104, 197, 144, 130, 37, 248, 246, 247, 9,
        13, 147, 156, 149, 78, 119, 178, 52, 220, 51, 239, 6, 93, 152, 171, 171,
        57, 153, 252, 247, 229, 82, 111, 195, 226, 51, 132, 113, 117, 34, 111,
        143, 125, 92, 221, 177, 152, 122, 249, 5, 237, 161, 208, 247, 10, 217,
        144, 47, 201, 149, 28, 28, 206, 238, 155, 47, 161, 87, 210, 234, 217,
        84, 59, 21, 121, 38, 108, 199, 250, 240, 24, 97, 48, 65, 68, 227, 22,
        143, 95, 155, 103, 50, 254, 162, 18, 211, 158, 89, 42, 180, 201, 171,
        55, 19, 48, 83, 88, 242, 255, 72, 109, 210, 199, 209, 221, 103, 214,
        10, 203, 23, 107, 195, 16, 162, 195, 240, 78, 214, 78, 165, 99, 78,
        62, 159, 201, 181, 55, 249, 107, 169, 217, 239, 63
    ]
    @test verify_webauthn_signature(pem, authData, clientDataJSON, sig_der)
    badsig = copy(sig_der)
    badsig[10] ⊻= 0xFF
    @test !verify_webauthn_signature(pem, authData, clientDataJSON, badsig)
    badauth = copy(authData)
    badauth[1] = 0xFF
    @test !verify_webauthn_signature(pem, badauth, clientDataJSON, sig_der)
end

@testset "End-to-end challenge check" begin
    challenge = generate_challenge(16)
    cd = JSON3.write(Dict("challenge" => challenge,
        "origin" => "https://demo", "type" => "webauthn!create"))
    b64cd = base64urlencode(Vector{UInt8}(cd))
    @test verify_challenge(b64cd, challenge)
end

@testset "OKP/Ed25519 end-to-end" begin
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    cose = Dict(1 => 1, 3 => -8, -1 => 6, -2 => pk)
    cose2 = CBOR.decode(CBOR.encode(cose))
    key = cose_key_parse(cose2)
    @test isa(key, OKPPublicKey)
    @test key.alg == -8
    @test key.crv == 6
    @test key.x == pk
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
    ad = rand(UInt8, 16)
    cdj = rand(UInt8, 32)
    msg = vcat(ad, SHA.sha256(cdj))
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    siglen = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, siglen, msg, length(msg), sk) == 0
    @test Int(siglen[]) == length(sig)
    @test verify_webauthn_signature(key, ad, cdj, sig)
    bad = copy(sig)
    bad[1] ⊻= 0xFF
    @test !verify_webauthn_signature(key, ad, cdj, bad)
end