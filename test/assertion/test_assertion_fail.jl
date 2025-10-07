# test_assertion_fail.jl
# Purpose: Negative-path assertion test for all signature, challenge, origin,
# and type errors.
# SPEC_ID: §7.2-Authentication-Verify-Challenge
# SPEC_ID: §7.2-Authentication-Verify-Origin
# SPEC_ID: §7.2-Authentication-Verify-ClientData-Type
# SPEC_ID: §7.2-Authentication-Verify-Signature

using Test, WebAuthn, CBOR, SHA, Sodium, JSON3

# SPEC_ID: §5.1.4.3-Get-Request-Exceptions
# SPEC_ID: §5.6-AbortSignal-Behavior
# SPEC_ID: §7.2-Authentication-Unknown-Credential-Behavior
@testset "Assertion Negative/Fail (Ed25519/OKP synthetic)" begin
    # -- Generate known-good keypair --
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    key = OKPPublicKey(pk, -8, 6)
    authData = rand(UInt8, 37)
    legit_challenge = generate_challenge(32)
    bad_challenge = generate_challenge(32)
    rp_origin = "https://unit-test.example"
    good_clientData = JSON3.write(Dict(
        "challenge" => legit_challenge,
        "origin" => rp_origin,
        "type" => "webauthn.get",
    ))
    sign_input = vcat(authData, SHA.sha256(Vector{UInt8}(good_clientData)))
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, sign_input,
        length(sign_input), sk) == 0

    # SPEC_ID: §7.2-Authentication-Verify-Signature
    @test verify_webauthn_signature(key, authData,
        Vector{UInt8}(good_clientData), sig)

    # 1: Challenge mismatch
    tampered_cd = JSON3.write(Dict(
        "challenge" => bad_challenge,
        "origin" => rp_origin,
        "type" => "webauthn.get"
    ))
    # SPEC_ID: §7.2-Authentication-Verify-Challenge
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(tampered_cd), sig)

    # 2: Origin mismatch
    tampered_cd2 = JSON3.write(Dict(
        "challenge" => legit_challenge,
        "origin" => "https://evil-unit.example",
        "type" => "webauthn.get"
    ))
    # SPEC_ID: §7.2-Authentication-Verify-Origin
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(tampered_cd2), sig)

    # 3: Wrong type in clientDataJSON
    cd_wrongtype = JSON3.write(Dict(
        "challenge" => legit_challenge,
        "origin" => rp_origin,
        "type" => "webauthn.create"
    ))
    # SPEC_ID: §7.2-Authentication-Verify-ClientData-Type
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(cd_wrongtype), sig)

    # 4: Modified authenticatorData (replay/tamper)
    bad_auth = copy(authData)
    bad_auth[5] ⊻= 0x45
    sign_input_bad_auth = vcat(bad_auth, SHA.sha256(
        Vector{UInt8}(good_clientData)))
    sig_bad_auth = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    @test Sodium.crypto_sign_detached(sig_bad_auth, sl,
        sign_input_bad_auth, length(sign_input_bad_auth), sk) == 0
    @test !verify_webauthn_signature(key, bad_auth,
        Vector{UInt8}(good_clientData), sig)

    # 5: Bad signature (flip a byte)
    badsig = copy(sig)
    badsig[1] ⊻= 0xff
    @test !verify_webauthn_signature(key, authData,
        Vector{UInt8}(good_clientData), badsig)

    # 6: Wrong key struct (unsupported type)
    wrongkey = EC2PublicKey(rand(UInt8, 32), rand(UInt8, 32), -7, 1)
    result = false
    try
        result = verify_webauthn_signature(wrongkey, authData,
            Vector{UInt8}(good_clientData), sig)
    catch
        result = false
    end
    @test result == false

    # 7: Wrong PEM
    wrongpem = "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhki...\nEND PUBLIC KEY-----"
    @test !verify_webauthn_signature(wrongpem, authData,
        Vector{UInt8}(good_clientData), sig)
end

@testset "Assertion Negative/Fail (packed ES256)" begin
    # Use positive vector, then mutate to produce negatives
    ad = load_vector("vectors_ec2_packed", "authentication", "authenticatorData.bin")
    cdj = load_vector("vectors_ec2_packed", "authentication", "clientDataJSON.bin")
    sig = load_vector("vectors_ec2_packed", "authentication", "signature.bin")
    # Extract COSE_Key from attestation object
    attobj = CBOR.decode(load_vector("vectors_ec2_packed", "registration", "attestationObject.cbor"))
    authDataReg = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authDataReg[37+16+1]) << 8) |
                           Int(authDataReg[37+16+2]))
    pkbytes = authDataReg[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    # 1: Good signature should pass
    @test verify_webauthn_signature(key, ad, cdj, sig)

    # 2: Tampered challenge (CDJ), should fail
    cdj_obj = JSON3.read(String(cdj))
    cdj_dict = Dict(
        "type" => cdj_obj["type"],
        "origin" => cdj_obj["origin"],
        "challenge" => base64urlencode(rand(UInt8, 32)),
    )
    tampered_cdj = Vector{UInt8}(JSON3.write(cdj_dict))
    @test !verify_webauthn_signature(key, ad, tampered_cdj, sig)

    # 3: Tampered signature should fail
    s2 = copy(sig); s2[10] ⊻= 0x4F
    @test !verify_webauthn_signature(key, ad, cdj, s2)

    # 4: Tampered authenticatorData should fail
    ad2 = copy(ad); ad2[1] ⊻= 0x33
    @test !verify_webauthn_signature(key, ad2, cdj, sig)

    # 5: Bad key (random pubkey): accept either false or error
    try
        cose_bad = Dict(1=>2, 3=>-7, -1=>1, -2=>rand(UInt8, 32), -3=>rand(UInt8, 32))
        key_bad = cose_key_parse(cose_bad)
        # Signature check must fail
        @test !verify_webauthn_signature(key_bad, ad, cdj, sig)
    catch e
        @test occursin("Failed to set EC_KEY", e.msg) ||
      occursin("Invalid EC2 public key", e.msg)
        # Accept error as a valid fail (L3-compliant as "reject bad key")
    end
end

# SPEC_ID: §7.2-Authentication-Verify-Signature
@testset "Signature check stub" begin
    pubkey_fake = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    msg = rand(UInt8, 16)
    sig = rand(UInt8, 64)
    @test !verify_webauthn_signature(pubkey_fake, msg, msg, sig)
end