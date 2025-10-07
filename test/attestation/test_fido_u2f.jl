# test_fido_u2f.jl
# ---------------------------------------------------------------------------
# Purpose: Systematic Level 3 validation of FIDO U2F/WebAuthn interoperability
#          using vectors for both registration (attestation)
#          and authentication (assertion).
#
# SPEC_ID: §8.6-fido-u2f-Format-Compatibility
#
using Test, WebAuthn, CBOR, JSON3

# SPEC_ID: §2.2.1-FIDO-U2F-UserHandle
@testset "FIDO2/U2F Registration/Attestation" begin
    attestationObject = load_vector("vectors_fidou2f", "registration", "attestationObject.cbor")
    clientDataJSON = load_vector("vectors_fidou2f", "registration", "clientDataJSON.bin")

    # SPEC_ID: §8.6-fido-u2f-Format-Compatibility
    # This implementation does not support pure 'fido-u2f' format attestation.
    # Test MUST exist (Level 3) and marked as broken until implemented.
    @test_broken verify_attestation_object(
        WebAuthn.base64urlencode(attestationObject),
        clientDataJSON
    ) == true

    # SPEC: extraction of keys is tested in authentication suite below.
end

# SPEC_ID: §6.1.2-U2F-Signature-Compatibility
# SPEC_ID: §8.6-fido-u2f-RegistrationSigFormat
@testset "FIDO2/U2F Authentication/Assertion" begin
    # Set up public key: extraction from registration vector (see above)
    attestationObject = load_vector("vectors_fidou2f", "registration", "attestationObject.cbor")
    attobj = CBOR.decode(attestationObject)
    authData = attobj["authData"]
    pklen_offset = 37 + 16 + 2
    cred_len = (Int(authData[37+16+1]) << 8) | Int(authData[37+16+2])
    pkoff = pklen_offset + cred_len
    pkbytes = authData[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    pubkey_pem = cose_key_to_pem(key)

    ## Happy path
    authenticatorData = load_vector("vectors_fidou2f", "authentication", "authenticatorData.bin")
    clientDataJSON_authn = load_vector("vectors_fidou2f", "authentication", "clientDataJSON.bin")
    signature = load_vector("vectors_fidou2f", "authentication", "signature.bin")
    @test verify_webauthn_signature(pubkey_pem,
        authenticatorData, clientDataJSON_authn, signature) == true

    ## Negative/edge: corrupted signature -- must fail (SPEC_ID: §8.6)
    sig2 = copy(signature)
    sig2[7] ⊻= 0x44
    @test !verify_webauthn_signature(pubkey_pem, authenticatorData,
        clientDataJSON_authn, sig2)

    ## Negative: corrupted challenge (SPEC_ID: §8.6)
    cdj_obj = JSON3.read(String(clientDataJSON_authn))
    tampered_cdj = Dict(
        "type" => cdj_obj["type"],
        "origin" => cdj_obj["origin"],
        "challenge" => base64urlencode(rand(UInt8, 32)),
    )
    tampered_cdj_bytes = Vector{UInt8}(JSON3.write(tampered_cdj))
    @test !verify_webauthn_signature(pubkey_pem, authenticatorData,
        tampered_cdj_bytes, signature)

    ## Negative: corrupted authenticatorData (SPEC_ID: §8.6)
    tampered_ad = copy(authenticatorData)
    tampered_ad[1] ⊻= 0x23
    @test !verify_webauthn_signature(pubkey_pem, tampered_ad,
        clientDataJSON_authn, signature)

    ## Negative: bad key (truncated/altered x-coord)
    try
        cose_bad = Dict(1 => 2, 3 => -7, -1 => 1,
            -2 => rand(UInt8, 32), -3 => rand(UInt8, 32))
        key_bad = cose_key_parse(cose_bad)
        @test !verify_webauthn_signature(key_bad, authenticatorData,
            clientDataJSON_authn, signature)
    catch e
        msg = getfield(e, :msg) isa String ? getfield(e, :msg) :
              sprint(showerror, e)
        @test occursin("Failed to set EC_KEY", msg) ||
              occursin("Invalid EC2 public key", msg)
    end

    ## (Optional) Negative: wrong PEM/algo
    wrong_pem = "-----BEGIN PUBLIC KEY-----\nZZZZZZZ\n-----END PUBLIC KEY-----"
    @test !verify_webauthn_signature(wrong_pem, authenticatorData,
        clientDataJSON_authn, signature)
end

@testset "FIDO2/U2F legacy (fmt:fido-u2f) unimplemented" begin
    # Explicit coverage: not implemented, so always marked broken
    # SPEC_ID: §8.6-fido-u2f-Format-Compatibility
    @test_broken false
end

# SPEC_ID: §10.1-Extension-Misuse-Ignored
# SPEC_ID: §10.1.1-Extension-appid
# SPEC_ID: §10.1.2-Extension-appidExclude
# SPEC_ID: §3-FIDO-AppID-Extension-Check
@testset "registration_options ignores unknown/wrong-context extensions" begin
    opts = registration_options("site.com", "Name", "123", "u", "u2";
        extensions=Dict("appid" => true))
    @test haskey(opts, "extensions")
    @test opts["extensions"]["appid"] == true
    # Should not throw or fail ceremony
end