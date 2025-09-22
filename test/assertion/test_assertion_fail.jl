# test_assertion_fail.jl
# --------------------------------------------------
# Purpose: Negative assertion vectors 
# (bad challenge, bad rpId, origin, signature, etc)
# Tests:
#   - Each type of error produces a correct, secure rejection 
# (never ghost success!)
using Test, WebAuthn, CBOR, SHA, Sodium, JSON3

@testset "Assertion Negative/Fail Cases" begin
    # -- Generate known-good keypair --
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    key = OKPPublicKey(pk, -8, 6)

    # -- Generate random "authenticatorData" and "clientDataJSON" --
    authData = rand(UInt8, 37)
    legit_challenge = generate_challenge(32)
    bad_challenge = generate_challenge(32)
    rp_origin = "https://unit-test.example"

    good_clientData = JSON3.write(Dict(
        "challenge" => legit_challenge,
        "origin" => rp_origin,
        "type" => "webauthn.get"
    ))
    # create good sig
    sign_input = vcat(authData, SHA.sha256(Vector{UInt8}(good_clientData)))
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, sign_input,
        length(sign_input), sk) == 0

    # -- Asserts: good signature passes --
    @test verify_webauthn_signature(key, authData,
        Vector{UInt8}(good_clientData), sig)

    # -- 1: Challenge mismatch --
    tampered_cd = JSON3.write(Dict(
        "challenge" => bad_challenge,
        "origin" => rp_origin,
        "type" => "webauthn.get"
    ))
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(tampered_cd), sig)

    # -- 2: Origin mismatch --
    tampered_cd2 = JSON3.write(Dict(
        "challenge" => legit_challenge,
        "origin" => "https://evil-unit.example",
        "type" => "webauthn.get"
    ))
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(tampered_cd2), sig)

    # -- 3: Wrong type in clientDataJSON --
    cd_wrongtype = JSON3.write(Dict(
        "challenge" => legit_challenge,
        "origin" => rp_origin,
        "type" => "webauthn.create"
    ))
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(cd_wrongtype), sig)

    # -- 4: Modified authenticatorData (replay, tamper) --
    bad_auth = copy(authData)
    bad_auth[5] ⊻= 0x45
    sign_input_bad_auth = vcat(bad_auth, SHA.sha256(
        Vector{UInt8}(good_clientData)))
    sig_bad_auth = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    @test Sodium.crypto_sign_detached(sig_bad_auth, sl,
        sign_input_bad_auth, length(sign_input_bad_auth), sk) == 0
    @test !verify_webauthn_signature(key, bad_auth,
        Vector{UInt8}(good_clientData), sig)

    # -- 5: Bad signature (flip a byte) --
    badsig = copy(sig)
    badsig[1] ⊻= 0xff
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(good_clientData), badsig)

    # -- 6: Wrong key struct (unsupported type) --
    wrongkey = EC2PublicKey(rand(UInt8, 32), rand(UInt8, 32), -7, 1)
    # This should error if you are strict, or always reject
    result = false
    try
        result = verify_webauthn_signature(wrongkey, authData,
            Vector{UInt8}(good_clientData), sig)
    catch
        result = false
    end
    @test result == false

    # -- 7: Wrong PEM --
    wrongpem = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhki...\nEND PUBLIC KEY-----"
    @test !verify_webauthn_signature(wrongpem, authData,
        Vector{UInt8}(good_clientData), sig)

    # -- 8: Signature counter replay (optional, add if you enforce signCount) --
    # Suppose oldSignCount=20, newSignCount=15, that's a clone: must reject!
    # Not implemented in this test (depends on RP storage logic)
end

@testset "Signature check stub" begin
    pubkey_fake = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    msg = rand(UInt8, 16)
    sig = rand(UInt8, 64)
    @test !verify_webauthn_signature(pubkey_fake, msg, msg, sig)
end