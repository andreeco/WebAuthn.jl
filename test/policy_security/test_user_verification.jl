# test_user_verification.jl
# Purpose: Test UP/UV flags in authenticatorData for compliance with
# WebAuthn/FIDO2 spec (allowed, forbidden, error on strict requirement, etc).
# SPEC_ID: §6.1-Flags-UP
# SPEC_ID: §6.1-Flags-UV
# SPEC_ID: §7.2-Authentication-Verify-UP-Bit
# SPEC_ID: §7.2-Authentication-Verify-UV-Bit-if-Required

using Test, SHA, WebAuthn

"Extract flags from WebAuthn authenticatorData; throw if too short"
function get_flags(ad::Vector{UInt8})
    length(ad) < 33 && throw(ArgumentError("authData too short"))
    return ad[33]
end

"Returns true if User Presence bit is set"
is_up(flags::Integer) = (flags & 0x01) != 0

"Returns true if User Verification bit is set"
is_uv(flags::Integer) = (flags & 0x04) != 0

# Compose authenticatorData for testing, with customizable flag byte
function make_authdata_with_flags(rp_id::String, flags::UInt8)
    rpidhash = SHA.sha256(Vector{UInt8}(rp_id))
    return vcat(
        rpidhash,
        flags,    # 33rd, UP/UV/AT/ED etc
        0x00, 0x00, 0x00, 0x02
    )
end

# SPEC_ID: §6.1-Flags-UP
# SPEC_ID: §6.1-Flags-UV
# SPEC_ID: §7.2-Authentication-Verify-UP-Bit
# SPEC_ID: §7.2-Authentication-Verify-UV-Bit-if-Required
# SPEC_ID: §4-UserVerification-Definition
# SPEC_ID: §6.2.3-Authentication-Factor-Capability
# SPEC_ID: §7.1-Registration-Verify-UP-UV-Bits
@testset "User Presence (UP) and User Verification (UV) Flags" begin
    rp_id = "login.example"

    # Case 1: UP set, UV not set (only presence, pass for non-UV)
    ad1 = make_authdata_with_flags(rp_id, 0x01)
    @test is_up(get_flags(ad1))
    @test !is_uv(get_flags(ad1))

    # Case 2: UP and UV both set (user verification: true)
    ad2 = make_authdata_with_flags(rp_id, 0x01 | 0x04)
    @test is_up(get_flags(ad2))
    @test is_uv(get_flags(ad2))

    # Case 3: Both UP and UV not set (must never pass)
    ad3 = make_authdata_with_flags(rp_id, 0x00)
    @test !is_up(get_flags(ad3))
    @test !is_uv(get_flags(ad3))

    # Case 4: UV set but not UP (impossible, fail safe)
    ad4 = make_authdata_with_flags(rp_id, 0x04)
    @test !is_up(get_flags(ad4))
    @test is_uv(get_flags(ad4))

    # Enforcer used by server (with/without UV requirement)
    function enforce_up_uv(authData::Vector{UInt8}; require_uv::Bool=false)
        flags = get_flags(authData)
        is_up(flags) || throw(ArgumentError("User Presence (UP) flag not set"))
        if require_uv
            is_uv(flags) || throw(ArgumentError(
                "User Verification (UV) required but not set"))
        end
        return true
    end

    # --- POSITIVE/PASS CASES ---
    @test enforce_up_uv(ad1)                     # UP, no UV required
    @test enforce_up_uv(ad2)                     # UP+UV, always pass
    @test enforce_up_uv(ad2; require_uv=true)    # UP+UV, UV required

    # --- NEGATIVE/FAIL CASES ---
    @test_throws ArgumentError enforce_up_uv(ad3)                     # Both unset
    @test_throws ArgumentError enforce_up_uv(ad3; require_uv=true)    # Both unset, UV required
    @test_throws ArgumentError enforce_up_uv(ad4)                     # UV only, no UP
    @test_throws ArgumentError enforce_up_uv(ad1; require_uv=true)    # UV missing

    # "UserVerification=preferred" (UP is enough, may have extra bits set)
    for f in (0x01, 0x05, 0x45)    # UP + arbitrary higher bits
        ad = make_authdata_with_flags(rp_id, f)
        @test is_up(get_flags(ad))
        @test enforce_up_uv(ad)
    end

    # AT/ED/other flags should never mask UP/UV semantics
    ad_at = make_authdata_with_flags(rp_id, 0x41)   # UP+AT
    @test enforce_up_uv(ad_at)
    ad_uv_at = make_authdata_with_flags(rp_id, 0x45) # UP+UV+AT
    @test enforce_up_uv(ad_uv_at; require_uv=true)
end

# SPEC_ID: §5.8.6-UserVerificationRequirement
@testset "up/uv enforcement: userVerification=required" begin
    ad_up_uv = make_authdata_with_flags("a", 0x05)
    # SPEC_ID: §5.8.6-UserVerificationRequirement
    @test enforce_up_uv(ad_up_uv; require_uv=true)
    ad_up = make_authdata_with_flags("a", 0x01)
    @test_throws ArgumentError enforce_up_uv(ad_up; require_uv=true)
end