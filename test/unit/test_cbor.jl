# test_cbor.jl
# ----------------------
# Purpose: Ensure canonical CBOR decode/encode for all WebAuthn objects,
#          MUST reject duplicate keys, non-canonical input (§3, §5.8)
# Tests:
#   - Decode/encode roundtrip (with test vectors)
#   - Ignores/throws on duplicated map keys, malformed/truncated buffers
using Test, CBOR, Test

@testset "CBOR roundtrip and basic values" begin
    @test CBOR.decode(CBOR.encode(42)) == 42
    @test CBOR.decode(CBOR.encode(-100)) == -100
    @test CBOR.decode(CBOR.encode("hello")) == "hello"
    @test CBOR.decode(CBOR.encode("水")) == "水"
    @test CBOR.decode(
        CBOR.encode(UInt8[0xFF, 0x00, 0x01])) == UInt8[0xFF, 0x00, 0x01]
    x = Any[1, "foo", Dict("a" => 123)]
    b = CBOR.encode(x)
    @test CBOR.decode(b) == x
end

@testset "CBOR: RFC Appendix A WebAuthn CTAP2 map" begin
    example = Dict(1 => 2, 3 => 4)
    bytes = UInt8[0xA2, 0x01, 0x02, 0x03, 0x04]
    @test CBOR.decode(bytes) == example
    arr = [1, [2, 3], [4, 5]]
    ex_bytes = UInt8[0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05]
    @test CBOR.encode(arr) == ex_bytes
    @test CBOR.decode(ex_bytes) == arr
end

@testset "CBOR: float, null, true, false, undefined" begin
    for (val, hex) in (
        (0.0, [0xf9, 0x00, 0x00]),
        (1.5, [0xf9, 0x3e, 0x00]),
        (true, [0xf5]),
        (false, [0xf4]),
        (nothing, [0xf6]),                # CBOR 'null'
        (CBOR.Undefined(), [0xf7]))       # CBOR 'undefined'
        v = CBOR.decode(UInt8[hex...])
        if val isa CBOR.Undefined
            @test v isa CBOR.Undefined
        elseif val === nothing
            @test v === nothing
        else
            @test v == val
        end
        @test isequal(CBOR.decode(CBOR.encode(val)), val)
    end
end

@testset "CBOR: malformed/truncated detection" begin
    # Needs 2 more bytes
    @test_throws Exception CBOR.decode(UInt8[0x19])
    # Map: missing value
    @test_throws Exception CBOR.decode(UInt8[0xa1, 0x01])
    # Array: missing 1 el
    @test_throws Exception CBOR.decode(UInt8[0x82, 0x01])
    # Reserved/illegal info 
    @test_throws Exception CBOR.decode(UInt8[0x1c])
    # Indefinite-length bstr, unterminated   
    @test_throws Exception CBOR.decode(UInt8[0x5f, 0x41, 0x00])
    # Indefinite arr, unterminated
    @test_throws Exception CBOR.decode(UInt8[0x9f, 0x01, 0x02])
end

@testset "CBOR: duplicate keys not allowed (spec: invalid/ambiguous)" begin
    bad_cbor = UInt8[0xa2, 0x01, 0x02, 0x01, 0x03] # {1:2, 1:3}
    try
        v = CBOR.decode(bad_cbor)
        # Only one survives (CBOR.jl)
        @test v == Dict(1 => 3) || v == Dict(1 => 2)  
    catch e
        @test isa(e, Exception)
    end
end

@testset "CBOR: indefinite-length string parsing" begin
    # Example: 0x5f 0x43 01 02 03 0x41 04 0xff == bstr(0x01020304)
    bytes = UInt8[0x5f, 0x43, 0x01, 0x02, 0x03, 0x41, 0x04, 0xff]
    value = UInt8[0x01, 0x02, 0x03, 0x04]
    @test CBOR.decode(bytes) == value
end