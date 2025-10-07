# test_base64url.jl
# ---------------------------------------------------------------------
# Purpose: Ensure base64url encoding/decoding matches 
# RFC4648 §5 and WebAuthn §3.
# All encoding/decoding, used for browser challenge, clientDataJSON, 
# and all b64 fields, must be strictly spec compliant.
# 
# SPEC_ID: §3-Base64url-Encoding
# SPEC_ID: §3-Base64url-Decoding-Invalid

using Test, WebAuthn

# SPEC_ID: §3-Base64url-Encoding
# SPEC_ID: §3-Base64url-Decoding-Invalid
@testset "Base64url RFC4648 vectors" begin
    # RFC 4648 §10 table: test vectors, canonical, no padding
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

# SPEC_ID: §3-Base64url-Encoding
# SPEC_ID: §3-Base64url-Decoding-Invalid
@testset "Base64url roundtrip (random and edge)" begin
    # Covers encoding/decoding of length 0, 1, 2, 3, 10, 32, 100
    for len in (0, 1, 2, 3, 10, 32, 100)
        b = rand(UInt8, len)
        s = base64urlencode(b)
        # SPEC_ID: §3-Base64url-Encoding
        @test base64urldecode(s) == b
        # Only valid alphabet
        @test all(c -> (c in ('A':'Z') || c in ('a':'z') || 
        c in ('0':'9') || c == '-' || c == '_'), s)
        # SPEC_ID: §3-Base64url-Encoding
        @test !occursin('=', s)
    end
    # Just an edge "paddingless" test
    @test WebAuthn.base64urldecode("AQIDBA") == UInt8[1, 2, 3, 4]
end

# SPEC_ID: §3-Base64url-Decoding-Invalid
@testset "Base64url decoder padding acceptance" begin
    # Decoder must accept normal base64 padding in input but strip it
    # no pad
    @test base64urldecode("Zm9v") == [0x66, 0x6f, 0x6f]
    # with pad
    @test base64urldecode("Zm9vYg==") == [0x66, 0x6f, 0x6f, 0x62]
    # no pad (short input)
    @test base64urldecode("Zm9vYg") == [0x66, 0x6f, 0x6f, 0x62]
end

# SPEC_ID: §3-Base64url-Decoding-Invalid
# SPEC_ID: §13.1-§13.4-Fuzz-Resistance
@testset "Base64url decode - illegal chars and excessive pad" begin
    # Negative-path SPEC_ID for decoding invalid base64url input
    # $ is illegal
    @test_throws ArgumentError base64urldecode("Zm\$9v")  
    # + is illegal        
    @test_throws ArgumentError base64urldecode("Zm9+=")  
    # Excessive '='         
    @test_throws ArgumentError base64urldecode("Zm9v===")      
    # Extra chars after pad   
    @test_throws ArgumentError base64urldecode("Zm9vYg==Z")       
    # Standalone pad not allowed
    @test_throws ArgumentError base64urldecode("=")               
end

# SPEC_ID: §3-Base64url-Decoding-Invalid
@testset "Base64url decode - malformed length" begin
    # Only one char: not valid base64url
    @test_throws ArgumentError base64urldecode("Z")    
    # two chars: valid           
    @test base64urldecode("Zm") == [0x66]    
    # two chars: valid (Zg => 'f')                     
    @test base64urldecode("Zg") == [0x66]                         
end

# SPEC_ID: §3-Base64url-Decoding-Invalid
@testset "Base64url decode - nonalphabet/CRLF" begin
    # carriage return/CR
    @test_throws ArgumentError base64urldecode("Zm9v\r")    
    # newline/LF      
    @test_throws ArgumentError base64urldecode("Zm9v\n")          
    # padding followed by garbage
    @test_throws ArgumentError base64urldecode("Zm9vYg=42")       
end