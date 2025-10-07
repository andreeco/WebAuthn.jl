# test_rp_id_hash.jl
# Purpose: Ensure rpIdHash in authenticatorData == SHA256(rp.id), per spec.
#
# SPEC_ID: §6.1-rpIdHash
# SPEC_ID: §7.1-Registration-Verify-rpIdHash
# SPEC_ID: §7.2-Authentication-Verify-rpIdHash

using Test, SHA, WebAuthn, CBOR

# Construct an authenticatorData with rpIdHash, flags, signCount, optional rest.
function make_authdata(rp_id::String; rest_bytes=UInt8[], overwrite_hash=nothing)
    hash = overwrite_hash === nothing ? SHA.sha256(Vector{UInt8}(rp_id)) : overwrite_hash
    return vcat(
        hash,
        UInt8(0x41),                # flags (UP=1 | AT=0x40)
        0x00, 0x00, 0x00, 0x01,     # signCount=1
        rest_bytes...)
end

# Returns true if rpIdHash matches SHA256(rp_id).
function rpIdHash_valid(authData::Vector{UInt8}, rp_id::String)
    got = authData[1:32]
    want = SHA.sha256(Vector{UInt8}(rp_id))
    return got == want
end

# SPEC_ID: §6.1-rpIdHash
# SPEC_ID: §7.1-Registration-Verify-rpIdHash
# SPEC_ID: §7.2-Authentication-Verify-rpIdHash
@testset "rpIdHash Enforcement (L3 required cases)" begin
    # 1. Pass: correct rpIdHash present
    rp_id = "example.com"
    ad = make_authdata(rp_id)
    @test rpIdHash_valid(ad, rp_id)

    # 2. Fail: rpId changed
    ad2 = make_authdata("evil.com")
    @test !rpIdHash_valid(ad2, rp_id)
    @test !rpIdHash_valid(ad, "evil.com")

    # 3. Fail: randomized or garbage hash
    badhash = rand(UInt8, 32)
    ad3 = make_authdata(rp_id; overwrite_hash=badhash)
    @test !rpIdHash_valid(ad3, rp_id)
    @test !rpIdHash_valid(ad3, "another.com")

    # 4. Too short (truncated authData): must throw
    ad4 = make_authdata(rp_id)[1:15]
    @test_throws BoundsError rpIdHash_valid(ad4, rp_id)

    # 5. Pass/fail with rest_bytes (e.g., as in attestation)
    fake_pk = rand(UInt8, 77)
    att_ad = make_authdata(rp_id, rest_bytes=fake_pk)
    @test rpIdHash_valid(att_ad, rp_id)
    @test !rpIdHash_valid(att_ad, "wrong.com")

    # 6. Parse from real-like attestation object
    cred_pk = CBOR.encode(Dict(1=>2, 3=>-7, -1=>1, -2=>rand(UInt8, 32), -3=>rand(UInt8, 32)))
    att_authData = make_authdata(rp_id, rest_bytes=cred_pk)
    @test rpIdHash_valid(att_authData, rp_id)
end

# Enforced variant: throws on mismatch.
function enforce_rpIdHash(authData::Vector{UInt8}, rp_id::String)
    got = authData[1:32]
    want = SHA.sha256(Vector{UInt8}(rp_id))
    got == want || throw(ArgumentError("rpIdHash check failed (expected SHA256($rp_id))"))
end

# SPEC_ID: §6.1-rpIdHash
# SPEC_ID: §7.1-Registration-Verify-rpIdHash
# SPEC_ID: §7.2-Authentication-Verify-rpIdHash
@testset "rpIdHash enforcement with error" begin
    rp_id = "demo.test"
    ad = make_authdata(rp_id)
    enforce_rpIdHash(ad, rp_id)   # Must NOT throw

    # Mismatched site string: should throw
    @test_throws ArgumentError enforce_rpIdHash(ad, "wrong-site")

    # Tampered hash: should throw
    badad = copy(ad)
    badad[1] ⊻= 0xFF
    @test_throws ArgumentError enforce_rpIdHash(badad, rp_id)
end