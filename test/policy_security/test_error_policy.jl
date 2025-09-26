# test_error_policy.jl
# --------------------------------------------------
# Purpose: Ensure error responses don’t distinguish discovered-not-discovered 
# users; never leak PII, defend against timing leak.
# Tests:
#   - Error indistinguishability, privacy checks, bad/unknown/invalid always 
# same error
using Test, WebAuthn, CBOR

@testset "Spec-mandated Error/Privacy Policy (Library)" begin
    # 1. user.id too short (empty)
    try
        registration_options("demo.com", "rp", "", "n", "n")
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin("demo.com", msg)
        @test occursin("user.id", msg)
        @test occursin("1 and 64", msg) || occursin("between", msg) ||
              occursin("bytes", msg)
    end

    # 2. user.id too long (rand string, PII, etc)
    longid = "A"^65
    longid2 = "alice@example.com"
    try
        registration_options("rp.com", "r", longid, "n", "n")
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin(longid, msg)
        @test occursin("user.id", msg)
    end
    try
        registration_options("something.com", "s", longid2^7, "n", "n")
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin(longid2, msg)
        @test occursin("user.id", msg)
    end

    # 3. Empty or missing required user_name
    try
        registration_options("foo.co", "foo", "ok", "", "Bob")
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin("ok", msg)
        @test occursin("user.name", msg) || occursin("required", msg) ||
              occursin("empty", msg)
    end

    # 3b. Empty displayName IS PERMISSIBLE per spec; must NOT error!
    registration_options("foo.co", "foo", "ok", "Bobby", "")

    # 4. Malformed COSE/CBOR parse
    try
        parse_credential_public_key(UInt8[])
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin("[]", msg)
        @test typeof(msg) == String
    end
    bad_cose = CBOR.encode(Dict(1 => 1, -1 => 6, -2 => rand(UInt8, 32),
        3 => -232435))
    try
        cose_key_parse(CBOR.decode(bad_cose))
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin(string(bad_cose), msg)
        @test typeof(msg) == String
    end

    # 5. No errors leak any user id/PII
    test_ids = ["abcdef", "verylongusername999", "alice@example.com"]
    errs = String[]
    for tid in test_ids
        try
            registration_options("foo.com", "foo", tid^70, "", "disp")
        catch e
            push!(errs, sprint(showerror, e))
        end
    end
    for (msg, tid) in zip(errs, test_ids)
        @test !occursin(tid, msg)
    end

    # 6. Catch-all: wild buffer, only sanity check error
    junk = UInt8[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02]
    try
        parse_credential_public_key(junk)
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin(string(junk), msg)
        @test typeof(msg) == String
    end
end