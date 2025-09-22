# test_rp_id_hash.jl
# -----------------------------------
# Purpose: Ensure rpIdHash extracted from authData == SHA256(rp.id).
# Spec: §6.1, §7.1, §7.2
# Tests:
#   - Pass: matching hash  
#   - Fail: different rp.id vs. stored hash
using Test, SHA, WebAuthn

using Test, SHA, WebAuthn

function make_authdata(rp_id::String; rest_bytes=UInt8[],
    overwrite_hash=nothing)
    # Create fake authenticatorData:
    # authData = rpIdHash (32) || flags (1) || signCount (4) || rest...
    hash = overwrite_hash === nothing ? SHA.sha256(Vector{UInt8}(rp_id)) :
           overwrite_hash
    return vcat(
        hash,
        UInt8(0x41),              # flags (UP=1 | AT=0x40)
        0x00, 0x00, 0x00, 0x01,   # signCount=1
        rest_bytes...)
end

# Library-level enforcement (here or in wrapper):
function rpIdHash_valid(authData::Vector{UInt8}, rp_id::String)
    got = authData[1:32]
    want = SHA.sha256(Vector{UInt8}(rp_id))
    return got == want
end

@testset "rpIdHash Enforcement" begin
    # 1. Pass: correct rpIdHash present
    rp_id = "example.com"
    ad = make_authdata(rp_id)
    @test rpIdHash_valid(ad, rp_id)

    # 2. Fail: rpId changed
    ad2 = make_authdata("evil.com")
    @test !rpIdHash_valid(ad2, rp_id)
    @test !rpIdHash_valid(ad, "evil.com")

    # 3. Fail: Randomized/garbage hash
    badhash = rand(UInt8, 32)
    ad3 = make_authdata(rp_id; overwrite_hash=badhash)
    @test !rpIdHash_valid(ad3, rp_id)
    # Would not match any real
    @test !rpIdHash_valid(ad3, "another.com")

    # 4. Fail: AuthData too short
    ad4 = make_authdata(rp_id)[1:15] # only half hash
    @test_throws BoundsError rpIdHash_valid(ad4, rp_id)

    # 5. Pass/fail with rest_bytes (credential parsing), for attestation flow
    fake_pk = rand(UInt8, 77)
    att_ad = make_authdata(rp_id, rest_bytes=fake_pk)
    @test rpIdHash_valid(att_ad, rp_id)
    @test !rpIdHash_valid(att_ad, "wrong.com")

    # 6. Integration: parse from real-like attestation object
    # Compose full fake authData w/CBOR COSE key
    cred_pk = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => rand(
            UInt8, 32), -3 => rand(UInt8, 32)))
    att_authData = make_authdata(rp_id, rest_bytes=cred_pk)
    @test rpIdHash_valid(att_authData, rp_id)
    # If you want: check that registration options with mismatched rpId 
    # will not pass
end

# Optional: Add helper for real libraries that want to "fail closed":
function enforce_rpIdHash(authData::Vector{UInt8}, rp_id::String)
    got = authData[1:32]
    want = SHA.sha256(Vector{UInt8}(rp_id))
    got == want || throw(ArgumentError("rpIdHash check failed 
    (expected SHA256($rp_id))"))
end

@testset "rpIdHash enforcement with error" begin
    rp_id = "demo.test"
    ad = make_authdata(rp_id)
    enforce_rpIdHash(ad, rp_id)  # Should succeed, no error

    # With mismatched rp_id
    @test_throws ArgumentError enforce_rpIdHash(ad, "wrong-site")
    # With tampered hash
    badad = copy(ad)
    badad[1] ⊻= 0xFF
    @test_throws ArgumentError enforce_rpIdHash(badad, rp_id)
end