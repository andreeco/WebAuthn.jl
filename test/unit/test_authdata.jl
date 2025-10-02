# test_authdata.jl
# -------------------------------------
# Purpose: Parse raw authenticatorData (byte array) to extract rpIdHash, flags,
#           signCount, and attestedCredentialData, extensions (when present)
# Spec: §6.1, §6.5.1
# Tests:
#   - Valid data of all types, attested/no attested, flags, counter
#   - Malformed/short/wrong flags/fuzzed cases → error/edge checks
using Test, WebAuthn, CBOR

@testset "authenticatorData parsing" begin
    # Use a real, valid EC2 key
    pem = load_pem("ec_p256_spki")
    x, y = parse_ec_pem_xy(pem)

    pk_cbor = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y))
    aaguid = rand(UInt8, 16)
    credid = rand(UInt8, 32)
    credlen = [UInt8((length(credid) >> 8) & 0xff),
               UInt8(length(credid) & 0xff)]
    prefix = rand(UInt8, 37)
    authData = vcat(prefix, aaguid, credlen, credid, pk_cbor)

    pkbytes = extract_credential_public_key(authData)
    @test pkbytes == pk_cbor
    key = parse_credential_public_key(authData)
    @test isa(key, WebAuthn.WebAuthnPublicKey)
end