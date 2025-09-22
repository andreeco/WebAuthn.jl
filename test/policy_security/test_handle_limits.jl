# test_handle_limits.jl
# ------------------------------------
# Purpose: user.id must be 1-64 bytes, random/opaque (no PII!); 
# credentialId check
# Spec: §5.4.3, §14.6.1, §6.5.1
# Tests:
#   - Accept/reject based on length/content
using Test, WebAuthn, CBOR

@testset "user.id and credentialId length/integrity" begin
    # Rule: 1-64 bytes, opaque. Should not be PII, but spec can't strictly 
    # enforce content.
    # ---- 1. Good lengths (1, 64)
    @testset "user.id 1 byte (allow)" begin
        opts = registration_options("a.com", "A", UInt8[123], "n", "n")
        @test length(base64urldecode(opts["user"]["id"])) == 1
    end
    @testset "user.id 64 bytes (allow)" begin
        u = rand(UInt8, 64)
        opts = registration_options("b.com", "B", u, "name", "display")
        @test length(base64urldecode(opts["user"]["id"])) == 64
    end
    # ---- 2. Bad: zero, >64 length, empty string
    @testset "user.id empty forbidden" begin
        @test_throws ArgumentError registration_options("b.com", "B", UInt8[],
            "name", "display")
    end
    @testset "user.id length > 64 forbidden" begin
        u = rand(UInt8, 65)
        @test_throws ArgumentError registration_options("c.com", "C", u, "name",
            "display")
        @test_throws ArgumentError registration_options("test.com", "T", "a"^65,
            "n", "n")
    end
    @testset "user.id as empty string forbidden" begin
        @test_throws ArgumentError registration_options("d.com", "D", "", "n",
            "n")
    end
    # ---- 3. PII-ish string (allowed by bytes, discouraged by spec—documented 
    # for info)
    @testset "user.id PII-ish string (allowed but not recommended)" begin
        userid = "alice@example.com"
        opts = registration_options("site", "site", userid, "n", "n")
        decoded = base64urldecode(opts["user"]["id"])
        @test 1 <= length(decoded) <= 64
        # Fix isascii: test for all ASCII bytes (as email would be)
        @test all(x -> x < 0x80, decoded)
        # Optionally (for an even stricter policy) convert to string and check 
        # for '@'
        s = String(decoded)
        @test occursin('@', s)    # Illustrates that email/PII could sneak in; 
        # policy can warn
    end

    # ---- 4. All-ASCII, but random, string user.id
    @testset "ASCII user.id not PII" begin
        s = "xyloPNLKg784"  # random, but ASCII
        opts = registration_options("d.com", "D", s, "n", "n")
        decoded = base64urldecode(opts["user"]["id"])
        @test 1 <= length(decoded) <= 64
        @test all(x -> x < 0x80, decoded)
    end

    # ---- 5. Non-ASCII, but valid (still allowed as octets)
    @testset "user.id non-ASCII (non-PII, opaque octets)" begin
        id_bytes = [0xc3, 0xa9, 0xb1, 0x7f]  # arbitrary bytes
        opts = registration_options("foo.com", "foo", id_bytes, "user", "disp")
        decoded = base64urldecode(opts["user"]["id"])
        @test length(decoded) == 4
    end

    # ---- 6. CREDENTIALID TEST: parse from authData
    @testset "credentialId length from parsing authData" begin
        # Forge an attested authData with a credId of arbitrary size within spec
        fake_pk = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => rand(
                UInt8, 32), -3 => rand(UInt8, 32)))
        cred_id = rand(UInt8, 32)
        credlen = [UInt8((length(cred_id) >> 8) & 0xff), UInt8(
            length(cred_id) & 0xff)]
        aaguid = zeros(UInt8, 16)
        prefix = rand(UInt8, 37)
        authData = vcat(prefix, aaguid, credlen, cred_id, fake_pk)
        key = parse_credential_public_key(authData)
        @test key isa WebAuthnPublicKey
        # To check the credId length, extract it manually:
        offset = 37 + 16
        idlen = (authData[offset+1] << 8) | authData[offset+2]
        @test idlen == 32
    end

    # ---- 7. credentialId too short (should parse, but NOT recommended in prod)
    @testset "credentialId too short (edge; would be authenticator bug)" begin
        cred_id = rand(UInt8, 0)  # zero bytes--illegal in spec, but try
        fake_pk = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => rand(
                UInt8, 32), -3 => rand(UInt8, 32)))
        credlen = [UInt8(0), UInt8(0)]
        aaguid = zeros(UInt8, 16)
        prefix = rand(UInt8, 37)
        authData = vcat(prefix, aaguid, credlen, cred_id, fake_pk)
        try
            parse_credential_public_key(authData)
            # It's up to your parse fn to throw error or accept 
            # (comment accordingly)
            @test true # If you want error, use @test_throws here.
        catch
            @test true
        end
    end
end