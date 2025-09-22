# test_user_verification.jl
# ----------------------------------
# Purpose: Check UP and UV flags logic, as required by allow userVerification 
# (required/preferred/none).
# Tests:
#   - Failure if UV/UP missing when required, pass otherwise
using Test, WebAuthn

using Test, WebAuthn

"Extract flags from WebAuthn authenticatorData"
function get_flags(ad::Vector{UInt8})
    length(ad) < 33 && throw(ArgumentError("authData too short"))
    flags = ad[33]
    return flags
end

"Returns true if UP (bit 0) is set"
is_up(flags::Integer) = (flags & 0x01) != 0

"Returns true if UV (bit 2) is set"
is_uv(flags::Integer) = (flags & 0x04) != 0

# Convenience factory for authData with customizable UP/UV
function make_authdata_with_flags(rp_id::String, flags::UInt8)
    rpidhash = SHA.sha256(Vector{UInt8}(rp_id))
    # Compose [rpIdHash (32) | flags (1) | signCount (4)]
    return vcat(
        rpidhash,
        flags,
        0x00, 0x00, 0x00, 0x02
    )
end

@testset "User Presence/Verification Flags" begin
    rp_id = "login.example"
    signCount = 10

    # ---- Case 1: UP set, UV not set (typical non-UV assertion)
    ad1 = make_authdata_with_flags(rp_id, 0x01)
    @test is_up(get_flags(ad1))
    @test !is_uv(get_flags(ad1))

    # ---- Case 2: UP and UV (both) set (userVerified login)
    ad2 = make_authdata_with_flags(rp_id, 0x01 | 0x04)
    @test is_up(get_flags(ad2))
    @test is_uv(get_flags(ad2))

    # ---- Case 3: UP not set, UV not set (invalid: must not accept)
    ad3 = make_authdata_with_flags(rp_id, 0x00)
    @test !is_up(get_flags(ad3))
    @test !is_uv(get_flags(ad3))

    # ---- Case 4: UV set but UP not set ("impossible," but fail safe)
    ad4 = make_authdata_with_flags(rp_id, 0x04)
    @test !is_up(get_flags(ad4))
    @test is_uv(get_flags(ad4))

    # ---- Logic for enforcing policy (server-side)
    function enforce_up_uv(authData::Vector{UInt8}; require_uv::Bool=false)
        flags = get_flags(authData)
        is_up(flags) || throw(ArgumentError("User Presence (UP) flag not set"))
        if require_uv
            is_uv(flags) || throw(ArgumentError("User Verification (UV) flag 
            required but not set"))
        end
        return true
    end

    # --- PASS cases ---
    @test enforce_up_uv(ad1)                # UP only, no UV required: pass
    @test enforce_up_uv(ad2)                # UP and UV: pass regardless
    @test enforce_up_uv(ad2; require_uv=true) # UP and UV: UV required: pass

    # --- FAIL cases ---
    # No UP: must fail
    @test_throws ArgumentError enforce_up_uv(ad3)
    @test_throws ArgumentError enforce_up_uv(ad3; require_uv=true)
    # UV only, but not UP: must fail
    @test_throws ArgumentError enforce_up_uv(ad4)
    # UP but no UV: if required, must fail      
    @test_throws ArgumentError enforce_up_uv(ad1; require_uv=true)

    # --- Realistic "userVerification=preferred" cases (UP is always enough) ---
    for f in (0x01, 0x05, 0x45) # with UP, maybe random extra bits
        ad = make_authdata_with_flags(rp_id, f)
        @test is_up(get_flags(ad))
        @test enforce_up_uv(ad)
    end

    # --- AT/ED/other flag bits coverage
    # AT flag (bit 6), ED (bit 7) are not checked here,
    # but should not mask UP/UV logic
    ad_at = make_authdata_with_flags(rp_id, 0x41)  # UP+AT
    @test enforce_up_uv(ad_at)
    ad_uv_at = make_authdata_with_flags(rp_id, 0x45) # UP+UV+AT
    @test enforce_up_uv(ad_uv_at; require_uv=true)
end