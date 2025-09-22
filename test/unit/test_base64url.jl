# test_base64url.jl
# -------------------------------------------------
# Purpose: Ensure base64url encoding/decoding matches
# RFC4648 §5 (WebAuthn spec §3),used for challenge, clientDataJSON, 
# and all b64 fields, no padding.
#
# MUST:
#   - Accept only legal characters [A-Za-z0-9-_], omit '='
#   - Encode/decode (roundtrip) arbitrary, empty, and edge byte arrays
#   - Fail or reject illegal/badly-padded/bad-chars input
#
# Vectors:
#   - Known-good roundtrips
#   - Browser, Python, or hand-chosen invalid b64url examples
#
using Test, WebAuthn

@testset "Base64url RFC4648 vectors" begin
    # Section 10 of RFC 4648, base64url encoding (no '=')
    @test base64urlencode(UInt8[]) == ""
    @test base64urldecode("") == UInt8[]
    # "f"
    @test base64urlencode([0x66]) == "Zg"
    # "fo"
    @test base64urlencode([0x66, 0x6f]) == "Zm8"
    # "foo"
    @test base64urlencode([0x66, 0x6f, 0x6f]) == "Zm9v"
    # "foob"
    @test base64urlencode([0x66, 0x6f, 0x6f, 0x62]) == "Zm9vYg"
    # "fooba"
    @test base64urlencode([0x66, 0x6f, 0x6f, 0x62, 0x61]) == "Zm9vYmE"
    # "foobar"
    @test base64urlencode([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]) == "Zm9vYmFy"
    @test base64urldecode("Zg") == [0x66]
    @test base64urldecode("Zm8") == [0x66, 0x6f]
    @test base64urldecode("Zm9v") == [0x66, 0x6f, 0x6f]
    @test base64urldecode("Zm9vYg") == [0x66, 0x6f, 0x6f, 0x62]
    @test base64urldecode("Zm9vYmE") == [0x66, 0x6f, 0x6f, 0x62, 0x61]
    @test base64urldecode("Zm9vYmFy") == [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]
end

@testset "Base64url roundtrip (random and edge)" begin
    for len in (0, 1, 2, 3, 10, 32, 100)
        b = rand(UInt8, len)
        s = base64urlencode(b)
        @test base64urldecode(s) == b
        @test all(c -> (c in ('A':'Z') || c in ('a':'z') ||
                        c in ('0':'9') || c == '-' || c == '_'), s)
        @test !occursin('=', s)
    end
    @test WebAuthn.base64urldecode("AQIDBA") == UInt8[1, 2, 3, 4]
end

@testset "Base64url decoder padding acceptance" begin
    # These must all decode fine (padding is allowed by decoder)
    # no padding
    @test base64urldecode("Zm9v") == [0x66, 0x6f, 0x6f]
    # with padding
    @test base64urldecode("Zm9vYg==") == [0x66, 0x6f, 0x6f, 0x62]
    # no padding
    @test base64urldecode("Zm9vYg") == [0x66, 0x6f, 0x6f, 0x62]
end

@testset "Base64url decode - illegal chars and excessive pad" begin
    # Tests that MUST fail (raise error)
    # $ not allowed
    @test_throws ArgumentError base64urldecode("Zm\$9v")
    # + not allowed in base64url
    @test_throws ArgumentError base64urldecode("Zm9+=")
    # excessive pad
    @test_throws ArgumentError base64urldecode("Zm9v===")
    # garbage after padding
    @test_throws ArgumentError base64urldecode("Zm9vYg==Z")
    # lonely equals
    @test_throws ArgumentError base64urldecode("=")
end

@testset "Base64url decode - malformed length" begin
    # 1-char, invalid
    @test_throws ArgumentError base64urldecode("Z")
    # 2-char, OK
    @test base64urldecode("Zm") == [0x66]
    # 2-char, OK
    @test base64urldecode("Zg") == [0x66]
end

@testset "Base64url decode - nonalphabet/CRLF" begin
    @test_throws ArgumentError base64urldecode("Zm9v\r")
    @test_throws ArgumentError base64urldecode("Zm9v\n")
    @test_throws ArgumentError base64urldecode("Zm9vYg=42")
end