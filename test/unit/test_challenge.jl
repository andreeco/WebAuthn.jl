using Test, WebAuthn

@testset "Challenge generation" begin
    nbytes = 32
    chals = Set{String}()
    iterations = 1000
    for i = 1:iterations
        c = generate_challenge(nbytes)
        # Must not repeat (collision)
        @test !(c in chals)  # §13.4.3
        push!(chals, c)
        # Length at least minimal for b64url
        minlen = ceil(Int, nbytes * 8 / 6 * 0.99)
        @test length(c) >= minlen
        @test length(c) <= nbytes * 2
        # All valid b64url alphabet
        for ch in c
            @test (ch in 'A':'Z' || ch in 'a':'z' || ch in '0':'9' ||
                   ch == '-' || ch == '_')
        end
        # No '=' allowed
        @test !occursin('=', c)
        # All ASCII printable
        @test all(isascii, c)
    end
    # No collisions
    @test length(chals) == iterations
    # Entropy sanity: not all same char
    for c in chals
        @test length(unique(c)) > 5
    end
end

@testset "generate_challenge returns different values each call" begin
    c1 = generate_challenge()
    c2 = generate_challenge()
    @test c1 != c2
end

@testset "Challenge length and encoding exact" begin
    n = 32
    c = generate_challenge(n)
    # For 32 bytes: b64url is about 43-44 chars, but could be a bit less
    @test 42 <= length(c) <= 44
end

@testset "Challenge output can be decoded" begin
    n = 32
    c = generate_challenge(n)
    decoded = base64urldecode(c)
    @test length(decoded) == n
end

@testset "Testvector challenge parsing" begin
    # testvectors/none-ES256/registration/clientDataJSON.bin
    # We extract known challenge string and b64url-decode
    using JSON3
    cdj_bin = load_vector("vectors_ec2_none", "registration",
        "clientDataJSON.bin")
    cdj = JSON3.read(String(cdj_bin))
    challenge = cdj["challenge"]
    decoded = base64urldecode(challenge)
    # Should be 32 bytes (per vector design)
    @test length(decoded) == 32
    # May check the value against testvector if present
end
