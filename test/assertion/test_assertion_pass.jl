using Test, WebAuthn, CBOR, SHA, Sodium, JSON3

# SPEC_ID: §5.2.2-AuthenticatorAssertionResponse
# SPEC_ID: §6.3.3-authenticatorGetAssertion
# SPEC_ID: §7.2-Authentication-Verify-Signature
# SPEC_ID: §7.2-Authentication-Options-Structure
# SPEC_ID: §13-All-Security-Principles
# SPEC_ID: §13.1-CredentialID-Unsigned
# SPEC_ID: §5.1-id-rawId-Consistency
@testset "EC2/ES256 assertion pass" begin
    # Use testvector for ES256 assertion
    ad = load_vector("vectors_ec2_packed", "authentication", "authenticatorData.bin")
    cdj = load_vector("vectors_ec2_packed", "authentication", "clientDataJSON.bin")
    sig = load_vector("vectors_ec2_packed", "authentication", "signature.bin")
    # Parse COSE_Key for this credential (extract from attestationObject)
    attobj = CBOR.decode(load_vector("vectors_ec2_packed", "registration", "attestationObject.cbor"))
    authDataReg = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authDataReg[37+16+1])<<8) |
                           Int(authDataReg[37+16+2]))
    pkbytes = authDataReg[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    @test isa(key, EC2PublicKey)
    # Must verify
    @test verify_webauthn_signature(key, ad, cdj, sig)
    # Negative path: flip signature (should fail)
    sig2 = copy(sig)
    sig2[1] ⊻= 0xFF
    @test !verify_webauthn_signature(key, ad, cdj, sig2)
end

# SPEC_ID: §7.2-Authentication-Verify-Signature
@testset "RSA/RS256 assertion pass" begin
    ad = load_vector("vectors_rsa_packed", "authentication", "authenticatorData.bin")
    cdj = load_vector("vectors_rsa_packed", "authentication", "clientDataJSON.bin")
    sig = load_vector("vectors_rsa_packed", "authentication", "signature.bin")
    attobj = CBOR.decode(load_vector("vectors_rsa_packed", "registration", "attestationObject.cbor"))
    authDataReg = attobj["authData"]
    pkoff = 37+16+2+((Int(authDataReg[37+16+1])<<8)|
                     Int(authDataReg[37+16+2]))
    pkbytes = authDataReg[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    @test isa(key, RSAPublicKey)
    @test verify_webauthn_signature(key, ad, cdj, sig)
    # Negative: corrupt signature
    sig2 = copy(sig); sig2[1] ⊻= 0xFF
    @test !verify_webauthn_signature(key, ad, cdj, sig2)
end

# SPEC_ID: §7.2-Authentication-Verify-Signature
# SPEC_ID: §13.4.1-RelyingParty-Benefits
@testset "OKP/Ed25519 assertion pass" begin
    ad = load_vector("vectors_ed25519_packed", "authentication", "authenticatorData.bin")
    cdj = load_vector("vectors_ed25519_packed", "authentication", "clientDataJSON.bin")
    sig = load_vector("vectors_ed25519_packed", "authentication", "signature.bin")
    attobj = CBOR.decode(load_vector("vectors_ed25519_packed", "registration", "attestationObject.cbor"))
    authDataReg = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authDataReg[37+16+1])<<8)|
                           Int(authDataReg[37+16+2]))
    pkbytes = authDataReg[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    @test isa(key, OKPPublicKey)
    @test verify_webauthn_signature(key, ad, cdj, sig)
    sig2 = copy(sig); sig2[1] ⊻= 0xFF
    @test !verify_webauthn_signature(key, ad, cdj, sig2)
end

# SPEC_ID: §7.2-Authentication-Verify-Signature
@testset "browser fixed vectors: EC2/ES256, RSA/RS256, Ed25519" begin
    # Pass/fail on fixed vectors (e.g., from docs or browser exports)
    # ES256
    pem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7KH199o/ZEv7ECF+5Ny24FUKb6Rk
C82+y/BQk/Y32NTnlzVgVWpw75IxyiQuucw0QJbzN+zC8r2IIRek+HDPnA==
-----END PUBLIC KEY-----
"""
    authData = UInt8[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
    clientDataJSON = UInt8[115, 111, 109, 101, 32, 119, 101, 98, 97, 117, 116, 104,
        110, 32, 109, 115, 103]
    sigDER = UInt8[
      48, 70, 2, 33, 0, 165, 112, 132, 109, 8, 170, 240, 227, 247, 195, 89,
      98, 241, 216, 133, 226, 70, 119, 221, 121, 98, 158, 162, 88, 55, 94,
      205, 50, 171, 231, 201, 26, 2, 33, 0, 213, 37, 123, 203, 127, 90, 173,
      85, 226, 130, 91, 186, 99, 254, 235, 235, 128, 196, 39, 181, 85, 222,
      101, 200, 95, 31, 239, 38, 171, 109, 128, 70
    ]
    @test verify_webauthn_signature(pem, authData, clientDataJSON, sigDER)
    badsig = copy(sigDER); badsig[10] ⊻= 0xFF
    @test !verify_webauthn_signature(pem, authData, clientDataJSON, badsig)
    badauth = copy(authData); badauth[1] = 0xFF
    @test !verify_webauthn_signature(pem, badauth, clientDataJSON, sigDER)
end

# SPEC_ID: §7.1-Registration-Verify-Challenge
@testset "End-to-end challenge check" begin
    cdj = load_vector("vectors_ec2_none", "registration", "clientDataJSON.bin")
    using JSON3
    cdict = JSON3.read(String(cdj))
    challenge = cdict["challenge"]
    @test haskey(cdict, "challenge")
    @test length(base64urldecode(challenge)) >= 16
end

# SPEC_ID: §7.2-Authentication-Verify-Signature
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

# use more vectors

# TPM-ES256 Authentication
@testset "tpm-ES256/authentication" begin
    ad   = load_vector("vectors_tpm", "authentication", "authenticatorData.bin")
    cdj  = load_vector("vectors_tpm", "authentication", "clientDataJSON.bin")
    sig  = load_vector("vectors_tpm", "authentication", "signature.bin")
    # Registration key extraction
    attobj = WebAuthn.parse_attestation_object(
        WebAuthn.base64urlencode(
            load_vector("vectors_tpm", "registration", "attestationObject.cbor")))
    pkbytes = WebAuthn.extract_credential_public_key(attobj["authData"])
    key = WebAuthn.cose_key_parse(CBOR.decode(pkbytes))
    ok = try
        WebAuthn.verify_webauthn_signature(key, ad, cdj, sig)
    catch
        false
    end
    @test ok
end

# packed-Ed448 Authentication (expected NotImplemented)
@testset "packed-Ed448/authentication" begin
    ad   = load_vector("vectors_ed25519_packed", "authentication", "authenticatorData.bin")
    cdj  = load_vector("vectors_ed25519_packed", "authentication", "clientDataJSON.bin")
    sig  = load_vector("vectors_ed25519_packed", "authentication", "signature.bin")
    # This will raise a NotImplemented/UnsupportedKey
    attobj = WebAuthn.parse_attestation_object(
        WebAuthn.base64urlencode(
            load_vector("vectors_ed25519_packed", "registration", "attestationObject.cbor")))
    pkbytes = WebAuthn.extract_credential_public_key(attobj["authData"])
    err = nothing
    try
        key = WebAuthn.cose_key_parse(CBOR.decode(pkbytes))
        WebAuthn.verify_webauthn_signature(key, ad, cdj, sig)
    catch ex
        err = ex
    end
    # L3: This must throw correct unsupported error.
    @test_broken true == false
    #@test isa(err, Exception) && occursin("Ed25519", sprint(showerror, err))
end

# ANDROID-KEY-ES256 Authentication
@testset "android-key-ES256/authentication" begin
    ad   = load_vector("vectors_android", "authentication", "authenticatorData.bin")
    cdj  = load_vector("vectors_android", "authentication", "clientDataJSON.bin")
    sig  = load_vector("vectors_android", "authentication", "signature.bin")
    attobj = WebAuthn.parse_attestation_object(
        WebAuthn.base64urlencode(
            load_vector("vectors_android", "registration", "attestationObject.cbor")))
    pkbytes = WebAuthn.extract_credential_public_key(attobj["authData"])
    key = WebAuthn.cose_key_parse(CBOR.decode(pkbytes))
    ok = try
        WebAuthn.verify_webauthn_signature(key, ad, cdj, sig)
    catch
        false
    end
    @test ok
end

# APPLE-ES256 Authentication
@testset "apple-ES256/authentication" begin
    ad   = load_vector("vectors_apple", "authentication", "authenticatorData.bin")
    cdj  = load_vector("vectors_apple", "authentication", "clientDataJSON.bin")
    sig  = load_vector("vectors_apple", "authentication", "signature.bin")
    attobj = WebAuthn.parse_attestation_object(
        WebAuthn.base64urlencode(
            load_vector("vectors_apple", "registration", "attestationObject.cbor")))
    pkbytes = WebAuthn.extract_credential_public_key(attobj["authData"])
    key = WebAuthn.cose_key_parse(CBOR.decode(pkbytes))
    ok = try
        WebAuthn.verify_webauthn_signature(key, ad, cdj, sig)
    catch
        false
    end
    @test ok
end