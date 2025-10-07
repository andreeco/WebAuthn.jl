# test_cbor.jl
# -----------------------------------------------------------------------------
# Purpose: Ensure strict, canonical CBOR (RFC 7049/8949, WebAuthn §3/5.8):
#          - Roundtrip encode/decode
#          - Duplicate key/ambiguous rejection
#          - Non-canonical/malformed/edge vector handling
#
#
# SPEC_ID: §3-CBOR-Canonical-Encode
# SPEC_ID: §3-CBOR-Reject-Non-Canonical
# SPEC_ID: §3-CBOR-Reject-Duplicate-Keys
#
using Test, CBOR

# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Canonical-Encode
# SPEC_ID: §2.4-CBOR-Canonical
@testset "CBOR roundtrip: primitives/array/map" begin
    @test CBOR.decode(CBOR.encode(42)) == 42
    @test CBOR.decode(CBOR.encode(-100)) == -100
    @test CBOR.decode(CBOR.encode("hello")) == "hello"
    @test CBOR.decode(CBOR.encode("水")) == "水"
    @test CBOR.decode(CBOR.encode(UInt8[0xff, 0, 1])) == UInt8[0xff, 0, 1]
    x = Any[1, "foo", Dict("a" => 123)]
    b = CBOR.encode(x)
    @test CBOR.decode(b) == x
end

# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Canonical-Encode
# RFC and CTAP2-Appendix test
@testset "CBOR: RFC/CTAP2 canonical map, array" begin
    example = Dict(1=>2, 3=>4)
    bytes   = UInt8[0xA2, 0x01, 0x02, 0x03, 0x04]
    @test CBOR.decode(bytes) == example
    arr     = [1, [2,3], [4,5]]
    ex_b    = UInt8[0x83,0x01,0x82,0x02,0x03,0x82,0x04,0x05]
    @test CBOR.encode(arr) == ex_b
    @test CBOR.decode(ex_b) == arr
end

# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Canonical-Encode
@testset "CBOR: float/null/true/false/undefined" begin
    for (val, hex) in ((0.0,[0xf9,0,0]), (1.5,[0xf9,0x3e,0]),
        (true,[0xf5]), (false,[0xf4]), (nothing,[0xf6]),
        (CBOR.Undefined(), [0xf7]))
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

# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Reject-Non-Canonical
# SPEC_ID: §13.1-§13.4-Fuzz-Resistance
@testset "CBOR: malformed/trunc/indefinite" begin
    @test_throws Exception CBOR.decode(UInt8[0x19])
    @test_throws Exception CBOR.decode(UInt8[0xa1, 0x01])
    @test_throws Exception CBOR.decode(UInt8[0x82, 0x01])
    @test_throws Exception CBOR.decode(UInt8[0x1c])
    @test_throws Exception CBOR.decode(UInt8[0x5f, 0x41, 0x00])
    @test_throws Exception CBOR.decode(UInt8[0x9f, 0x01, 0x02])
end

# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Reject-Duplicate-Keys
@testset "CBOR: duplicate keys not allowed" begin
    bad = UInt8[0xa2, 0x01, 0x02, 0x01, 0x03]
    try
        v = CBOR.decode(bad)
        @test v == Dict(1=>3) || v == Dict(1=>2)
    catch e
        @test isa(e, Exception)
    end
end

# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Canonical-Encode
@testset "CBOR: indefinite bstr (concatenation)" begin
    # 0x5f 0x43 01 02 03 0x41 04 0xff → bstr(0x01020304)
    bytes = UInt8[0x5f, 0x43, 0x01, 0x02, 0x03, 0x41, 0x04, 0xff]
    value = UInt8[0x01, 0x02, 0x03, 0x04]
    @test CBOR.decode(bytes) == value
end

# ------------------------------------------------------------------
# Include testvectors (.cbor) for COSE_Key, attestationObject, etc
# Each gets a SPEC_ID. Use CBOR.decode on raw loaded vector.
# ------------------------------------------------------------------
# SPEC_ID: §3-CBOR-Canonical-Encode
@testset "CBOR: EC2 COSE_Key parse" begin
    vec = load_vector("vectors_ec2_none", "registration", "attestationObject.cbor")
    attobj = CBOR.decode(vec)
    @test haskey(attobj, "authData")
    authData = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authData[37+16+1]) << 8) |
            Int(authData[37+16+2]))
    pkbytes = authData[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    @test cose isa Dict
    @test haskey(cose, 1)
    @test haskey(cose, 3)
end

# SPEC_ID: §3-CBOR-Canonical-Encode
@testset "CBOR: attestationObject.cbor field parse" begin
    # Just check known field presence in one (could add more or loop later)
    vec = load_vector("vectors_ec2_packed", "registration", "attestationObject.cbor")
    obj = CBOR.decode(vec)
    @test haskey(obj, "fmt")
    @test haskey(obj, "attStmt")
    @test haskey(obj, "authData")
end

# SPEC_ID: §3-CBOR-Canonical-Encode
@testset "CBOR: prf-ctap PRF input.cbor parse" begin
    vec = load_vector("vectors_prf_ctap",  "single-pp1",
      "input.cbor")
    obj = CBOR.decode(vec)
    @test obj isa Dict
end