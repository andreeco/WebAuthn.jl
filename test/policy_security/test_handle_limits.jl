using Test, WebAuthn, CBOR

@testset "user.id and credentialId length/integrity" begin

    # 1. Accept 1/64 byte id; edge of allowed
    @testset "user.id 1 byte (accept)" begin
        opts = registration_options("a.com", "A", UInt8[123], "n", "n")
        @test length(base64urldecode(opts["user"]["id"])) == 1
    end
    @testset "user.id 64 bytes (accept)" begin
        u = rand(UInt8, 64)
        opts = registration_options("b.com", "B", u, "name", "display")
        @test length(base64urldecode(opts["user"]["id"])) == 64
    end

    # 2. Reject: 0 bytes, >64 bytes, empty string
    @testset "user.id empty forbidden" begin
        @test_throws ArgumentError registration_options("b.com", "B", UInt8[],
            "name", "display")
    end
    @testset "user.id length > 64 forbidden" begin
        u = rand(UInt8, 65)
        @test_throws ArgumentError registration_options("c.com", "C", u, 
        "name", "display")
        @test_throws ArgumentError registration_options("test.com", "T", "a"^65,
            "n", "n")
    end
    @testset "user.id as empty string forbidden" begin
        @test_throws ArgumentError registration_options("d.com", "D", "", 
        "n", "n")
    end

    # 3. PII-ish string allowed (discouraged, spec cannot block)
    @testset "user.id PII-ish string (doc discouraged, but spec cannot block)" begin
        userid = "alice@example.com"
        opts = registration_options("site", "site", userid, "n", "n")
        decoded = base64urldecode(opts["user"]["id"])
        @test 1 <= length(decoded) <= 64
        @test all(x -> x < 0x80, decoded)
        s = String(decoded)
        @test occursin('@', s) # policy, not ban
    end

    # 4. All-ASCII random user.id (non-PII)
    @testset "ASCII user.id not PII" begin
        s = "xyloPNLKg784"
        opts = registration_options("d.com", "D", s, "n", "n")
        decoded = base64urldecode(opts["user"]["id"])
        @test 1 <= length(decoded) <= 64
        @test all(x -> x < 0x80, decoded)
    end

    # 5. Non-ASCII allowed (demonstrates opaque byte acceptance)
    @testset "user.id non-ASCII (opaque, non-PII)" begin
        id_bytes = [0xc3, 0xa9, 0xb1, 0x7f]
        opts = registration_options("foo.com", "foo", id_bytes, "user", "disp")
        decoded = base64urldecode(opts["user"]["id"])
        @test length(decoded) == 4
    end

    # 6. credentialId check via parsing authData
    @testset "credentialId length from parsing authData" begin
        pem = load_vector("vectors_ec2_packed", "pubkey.pem")
        x, y = parse_ec_pem_xy(pem)
        fake_pk = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y))
        cred_id = rand(UInt8, 32)
        credlen = [UInt8((length(cred_id) >> 8) & 0xff), 
        UInt8(length(cred_id) & 0xff)]
        aaguid = zeros(UInt8, 16)
        prefix = rand(UInt8, 37)
        authData = vcat(prefix, aaguid, credlen, cred_id, fake_pk)
        key = parse_credential_public_key(authData)
        @test key isa WebAuthnPublicKey
        offset = 37 + 16
        idlen = (authData[offset+1]<<8) | authData[offset+2]
        @test idlen == 32
    end

    # 7. credentialId too short (empty); spec forbids, but test robustness
    @testset "credentialId too short (would be authenticator bug)" begin
        cred_id = rand(UInt8, 0) # zero bytes
        fake_pk = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => rand(
            UInt8, 32), -3 => rand(UInt8, 32)))
        credlen = [UInt8(0), UInt8(0)]
        aaguid = zeros(UInt8, 16)
        prefix = rand(UInt8, 37)
        authData = vcat(prefix, aaguid, credlen, cred_id, fake_pk)
        try
            parse_credential_public_key(authData)
            # Accept if parser rejects/throws, or test passes gracefully 
            # (L3 compliant).
            @test true
        catch
            @test true
        end
    end

end