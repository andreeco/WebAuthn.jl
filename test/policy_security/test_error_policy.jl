using Test, WebAuthn, CBOR

@testset "Spec-mandated Error/Privacy Policy (Library)" begin
    # 1. user.id too short (empty string)
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

    # 2. user.id too long (PII/long/repeated value)
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

    # 3. user_name empty or missing
    try
        registration_options("foo.co", "foo", "ok", "", "Bob")
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin("ok", msg)
        @test occursin("user.name", msg) || occursin("required", msg) ||
              occursin("empty", msg)
    end

    # 3b. Empty displayName must NOT error (allowed by spec)
    registration_options("foo.co", "foo", "ok", "Bobby", "")

    # 4. Malformed COSE/CBOR parse, error must not leak input data
    try
        parse_credential_public_key(UInt8[])
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin("[]", msg)
        @test typeof(msg) == String
    end
    bad_cose = CBOR.encode(
        Dict(1 => 1, -1 => 6, -2 => rand(UInt8, 32), 3 => -232435))
    try
        cose_key_parse(CBOR.decode(bad_cose))
        @test false
    catch e
        msg = sprint(showerror, e)
        @test !occursin(string(bad_cose), msg)
        @test typeof(msg) == String
    end

    # 5. All errors PII sanitized (no user id leaks, even on fail)
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

    # 6. Random/fuzz buffer for credential parse: error text must not leak bytes
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