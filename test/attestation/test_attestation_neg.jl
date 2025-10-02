# test_attestation_neg.jl
# --------------------------------------------------
# Purpose: Negative/broken/edge-case attestation test vectors: corrupted sig, 
# bad fmt, missing fields
# Tests:
#   - Each supported attestation format fails gracefully/securely for malformed, 
# tampered, missing, or invalid data

using Test, WebAuthn, CBOR, SHA, Sodium, JSON3

@testset "Attestation Negative/Edge Cases" begin
    # -- 1. Corrupted signature (alg mismatch, random bytes, tampered) --
    cdj = JSON3.write(Dict("type" => "webauthn.create",
        "challenge" => "always-fail"))
    cdj_b = Vector{UInt8}(cdj)

    # Use a "good" key with bad/corrupted data
    x = rand(UInt8, 32)
    y = rand(UInt8, 32)
    cose_key = Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y)
    cbor_pk = CBOR.encode(cose_key)
    prefix = rand(UInt8, 37)
    aaguid = zeros(UInt8, 16)
    credlen = UInt8[0x00, 0x00]
    authData = vcat(prefix, aaguid, credlen, cbor_pk)
    msg = vcat(authData, SHA.sha256(cdj_b))

    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk) == 0
    # broken: use EdDSA signature but "alg" says ES256 (mismatch)
    attStmt = Dict("sig" => sig, "alg" => -7)
    attobj = Dict("fmt" => "packed", "authData" => authData,
        "attStmt" => attStmt)
    b64_attobj = base64urlencode(CBOR.encode(attobj))
    @test !verify_attestation_object(b64_attobj, cdj_b)

    # -- 2. AttStmt has unknown alg --
    attStmt2 = Dict("sig" => sig, "alg" => -999)
    attobj2 = Dict("fmt" => "packed", "authData" => authData,
        "attStmt" => attStmt2)
    b64_attobj2 = base64urlencode(CBOR.encode(attobj2))
    @test !verify_attestation_object(b64_attobj2, cdj_b)

    # -- 3. AttStmt missing sig
    attStmt3 = Dict("alg" => -7)
    attobj3 = Dict("fmt" => "packed", "authData" => authData,
        "attStmt" => attStmt3)
    b64_attobj3 = base64urlencode(CBOR.encode(attobj3))
    @test !verify_attestation_object(b64_attobj3, cdj_b)

    # -- 4. AttStmt missing alg
    attStmt4 = Dict("sig" => sig)
    attobj4 = Dict("fmt" => "packed", "authData" => authData,
        "attStmt" => attStmt4)
    b64_attobj4 = base64urlencode(CBOR.encode(attobj4))
    @test !verify_attestation_object(b64_attobj4, cdj_b)

    # -- 5. Bad format name
    attobj5 = Dict("fmt" => "unknownfmt", "authData" => authData,
        "attStmt" => attStmt)
    b64_attobj5 = base64urlencode(CBOR.encode(attobj5))
    @test !verify_attestation_object(b64_attobj5, cdj_b)

    # -- 6. Bad CBOR (truncated)
    bad_cbor = base64urlencode(CBOR.encode(Dict("fmt" => "packed",
        "authData" => authData, "attStmt" => attStmt))[1:end-10])
    @test !verify_attestation_object(bad_cbor, cdj_b)

    # -- 7. Packed attestation with x5c cert (invalid cert data)
    attStmt7 = Dict("sig" => sig, "alg" => -7, "x5c" => [rand(UInt8, 100)])
    attobj7 = Dict("fmt" => "packed", "authData" => authData,
        "attStmt" => attStmt7)
    b64_attobj7 = base64urlencode(CBOR.encode(attobj7))
    # This must fail soft (return false for damaged cert), not error
    @test !verify_attestation_object(b64_attobj7, cdj_b)

    # -- 8. attStmt empty
    attobj8 = Dict("fmt" => "packed", "authData" => authData,
        "attStmt" => Dict())
    b64_attobj8 = base64urlencode(CBOR.encode(attobj8))
    @test !verify_attestation_object(b64_attobj8, cdj_b)

    # -- 9. Completely mismatched (missing all required fields)
    badobj = Dict("foo" => "bar")
    b64_bad = base64urlencode(CBOR.encode(badobj))
    @test !verify_attestation_object(b64_bad, cdj_b)
end


@testset "WebAuthn packed self-attestation alg/key mismatch" begin
    cdj = JSON3.write(Dict("type" => "webauthn!create", "challenge" => "abc"))
    cdj_b = Vector{UInt8}(cdj)
    prefix = rand(UInt8, 37)
    aaguid = zeros(UInt8, 16)
    credlen = UInt8[0x00, 0x00]
    x = rand(UInt8, 32)
    y = rand(UInt8, 32)
    cose_key = Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y)
    cbor_pk = CBOR.encode(cose_key)
    authData = vcat(prefix, aaguid, credlen, cbor_pk)
    msg = vcat(authData, SHA.sha256(cdj_b))

    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk) == 0

    attStmt = Dict("sig" => sig, "alg" => -8)
    attobj = Dict("fmt" => "packed",
        "authData" => authData,
        "attStmt" => attStmt)
    b64_attobj = base64urlencode(CBOR.encode(attobj))
    @test !verify_attestation_object(b64_attobj, cdj_b)
end