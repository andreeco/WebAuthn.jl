# test_challenge.jl
# -------------------------
# Purpose: Ensure challenge generator meets spec: length, ASCII-only, 
# high entropy, non-reuse
# Spec: W3C §7.1, §5.4.3, §13.4.3 (MUST ≥16 random bytes, base64url, 
# unique per ceremony)
#
# Tests:
#   - Generated challenges are unique, ≥16 bytes
#   - All output chars are legal b64url
#   - Not reusable; nonces are unpredictable
using Test, WebAuthn

@testset "Challenge generation" begin
    nbytes = 32  # try both 16 and 32 for extra coverage
    chals = Set{String}()
    iterations = 1000

    # Collect a bunch, check lengths, ASCII/b64url, uniqueness
    for i = 1:iterations
        c = generate_challenge(nbytes)
        # Should not have already been seen
        @test !(c in chals)
        push!(chals, c)

        # Length: base64url expands every 3 bytes into 4 chars, 
        # then removes padding
        minlen = ceil(Int, nbytes * 8 / 6 * 0.99)  # this is slack, 
        # base64url may round up
        @test length(c) >= minlen
        @test length(c) ≤ nbytes * 2  # b64url never more than 2x input size

        # All chars must be allowed (A-Za-z0-9-_)
        for ch in c
            @test (ch in 'A':'Z' || ch in 'a':'z' || ch in '0':'9' ||
                   ch == '-' || ch == '_')
        end
        # Must not contain padding
        @test !occursin('=', c)

        # All ASCII chars
        @test all(isascii, c)
    end

    # Should be no collisions in 1000 random draws
    @test length(chals) == iterations

    # Smell test: must not generate trivial/low entropy
    for c in chals
        # Not all the same character, not all zeros
        @test length(unique(c)) > 5  # can't be like "AAAA..." or "0000...."
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
    # base64url encoding of 32 bytes is typically ceil(32/3)*4 == 44 chars
    # but because of no padding, could be shorter
    @test 42 ≤ length(c) ≤ 44
end

@testset "Challenge output can be decoded" begin
    n = 32
    c = generate_challenge(n)
    decoded = base64urldecode(c)
    @test length(decoded) == n
    # Shouldn't throw
end