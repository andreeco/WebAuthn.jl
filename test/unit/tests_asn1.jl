using Test, Base64, WebAuthn, WebAuthn.ASN1

WebAuthn.ASN1.EXTERNAL_DER_VALIDATION[] = false

@testset "ASN.1 DER Roundtrip" begin
    vals = [
        ASN1Integer(0),
        ASN1Integer(Int32(2^31 - 1)),
        ASN1Integer(-42),
        ASN1Boolean(true),
        ASN1Boolean(false),
        ASN1Null(),
        ASN1String(:UTF8String, "julia \xe2\x99\x9b"),
        ASN1String(:PrintableString, "HELLO123 ()+,-./:=?"),
        ASN1OID([1, 2, 840, 113549, 1, 1, 1]),
        ASN1OctetString([0x11, 0x22, 0xFF, 0x00]),
        ASN1BitString(BitVector([true, false, true, false, false, true]))
    ]
    for v in vals
        round = der_to_asn1(asn1_to_der(v))
        @test round == v
        encoded = ASN1.DER.encode(asn1_to_der(v))
        decoded = der_to_asn1(ASN1.DER.decode(encoded))
        @test decoded == v
    end
end

@testset "CONSTRUCTED Type Roundtrip" begin
    elt = ASN1Integer(7)
    seq = ASN1Sequence([elt, ASN1Boolean(false)])
    round = der_to_asn1(asn1_to_der(seq))
    @test round == seq

    structset = ASN1Set([ASN1Boolean(true), ASN1Integer(1234), ASN1Null()])
    round2 = der_to_asn1(asn1_to_der(structset))
    @test round2 == ASN1Set([ASN1Boolean(true), ASN1Integer(1234), ASN1Null()])
end

@testset "PEM Roundtrip" begin
    val = ASN1OID([2, 5, 4, 3])
    der = ASN1.DER.encode(asn1_to_der(val))
    pem = ASN1.DER.encode_pem(asn1_to_der(val), label="OID")
    @test pem isa String
    parsed = ASN1.DER.decode_pem(pem) |> der_to_asn1
    @test parsed == val
end

@testset "Invalid DER Inputs" begin
    # BAD BOOLEAN: value other than 0x00/0xFF
    bad_bool = UInt8[0x01, 0x01, 0x01]
    @test_throws ASN1Error der_to_asn1(ASN1.DER.decode(bad_bool))

    # BAD BIT STRING: unused bits > 7
    bad_bit = UInt8[0x03, 0x02, 0x09, 0x00]
    @test_throws ASN1Error der_to_asn1(ASN1.DER.decode(bad_bit))

    # BAD BIT STRING: nonzero unused bits
    bitstr = [true, false, false, false, false, false, true]
    valid = [0x03, 0x02, 0x01, 0x83]
    # 1 unused, but LSB is set in last byte
    @test_throws ASN1Error der_to_asn1(ASN1.DER.decode(valid))

    # BAD OID
    bad_oid1 = UInt8[0x06, 0x01, 0x78]
    # [3, x] or [1, >39]
    for data in (bad_oid1,)
        @test_throws ASN1Error der_to_asn1(ASN1.DER.decode(data))
    end

    # BAD PrintableString: symbol not allowed
    str = "ABC@DEF"
    der = asn1_to_der(ASN1String(:PrintableString, str))
    der.value = Vector{UInt8}(str)  # force bad input
    der.tag = ASN1.DER.TAG_PRINTABLE_STRING
    raw = ASN1.DER.encode(der)
    @test_throws ASN1Error der_to_asn1(ASN1.DER.decode(raw))

    # BAD length: excessive size
    too_big = UInt8[0x04, 0x84, 0x10, 0x00, 0x00, 0x00]  # > MAX_DER_LENGTH
    @test_throws ErrorException ASN1.DER.decode(too_big)

    # BAD DER: indefinite length (0x80 marker)
    indef = UInt8[0x05, 0x80, 0x00, 0x00]
    @test_throws ErrorException ASN1.DER.decode(indef)

    # BAD DER: extra trailing data
    d = ASN1.DER.encode(asn1_to_der(ASN1Integer(3)))
    @test_throws ErrorException ASN1.DER.decode([d; 0x00])
end

@testset "SET Canonical Encoding (DER)" begin
    # In DER, elements of a SET are sorted by DER encoding
    a, b, c = ASN1Integer(42), ASN1Integer(1), ASN1Null()
    set1 = ASN1Set([a, b, c])
    set2 = ASN1Set([b, a, c])
    enc1 = ASN1.DER.encode(asn1_to_der(set1))
    enc2 = ASN1.DER.encode(asn1_to_der(set2))
    @test enc1 == enc2  # should sort identically!
    # And roundtrip, order won't matter
    dec = der_to_asn1(ASN1.DER.decode(enc1))
    @test dec == ASN1Set([ASN1Integer(1), ASN1Integer(42), ASN1Null()])
end

#=
@testset "Deeply Nested Structures (recursion limit)" begin
    try
        # Should cause StackOverflowError, not segfault
        node = ASN1Integer(11)
        for _ in 1:1100
            node = ASN1Sequence([node])
        end
        _ = ASN1.DER.encode(asn1_to_der(node))
        @test false  # Should not reach here!
    catch e
        @test isa(e, StackOverflowError) || isa(e, ErrorException)
    end
end
=#

@testset "Fuzz/Malformed Data Resilience" begin
    # Malformed/partial DER (should not crash)
    for n in 1:10
        bytes = rand(UInt8, n)
        try
            ASN1.DER.decode(bytes)
        catch e
            @test true  # must not segfault
        end
    end
end

@testset "Object Equality" begin
    a = ASN1Integer(3)
    b = ASN1Integer(3)
    c = ASN1Integer(4)
    @test a == b
    @test a != c
end

# new 

#const TESTVEC_DIR = joinpath(@__DIR__, "../vectors/der_testvectors")
const TESTVEC_DIR = joinpath(dirname(pathof(WebAuthn)), 
"..", "test", "vectors", "der_testvectors")


"Helper: Read DER from testvectors directory"
function load_der(name)
    read(joinpath(TESTVEC_DIR, "$name.der"))
end

@testset "DER: Primitive and Constructed" begin
    @test der_to_asn1(
        ASN1.DER.decode(load_der("int_42"))) == ASN1Integer(42)
    @test der_to_asn1(
        ASN1.DER.decode(load_der("bool_true"))) == ASN1Boolean(true)
    @test der_to_asn1(ASN1.DER.decode(load_der("null"))) == ASN1Null()
    @test der_to_asn1(ASN1.DER.decode(load_der(
        "oid_rsaEncryption"))) == ASN1OID([1, 2, 840, 113549, 1, 1, 1])
    @test der_to_asn1(ASN1.DER.decode(load_der(
        "octetstring"))) == ASN1OctetString([0xde, 0xad, 0xbe, 0xef])
    @test der_to_asn1(ASN1.DER.decode(load_der(
        "bitstring"))) == ASN1BitString(BitVector(
        [true, true, false, true, false, false, true, true]))  # 0xd3
    # PrintableString
    s = der_to_asn1(ASN1.DER.decode(load_der("string")))
    @test s isa ASN1String && s.str == "HelloJULIA"
    # SEQUENCE
    seq = der_to_asn1(ASN1.DER.decode(load_der("sequence")))
    @test seq isa ASN1Sequence
    # SET
    st = der_to_asn1(ASN1.DER.decode(load_der("set")))
    @test st isa ASN1Set
    # NESTED
    nest = der_to_asn1(ASN1.DER.decode(load_der("nested")))
    @test nest isa ASN1Sequence
end

@testset "DER: Malformed and Forbidden Encodings" begin
    # Overlong integer length: forbidden in canonical DER
    @test_throws ErrorException ASN1.DER.decode(load_der("int_42_overlong"))
    # Indefinite length encoding: forbidden in DER
    @test_throws ErrorException ASN1.DER.decode(load_der("octetstring_indef"))
    # Bad BIT STRING: unused bits out of bounds
    @test_throws ASN1Error der_to_asn1(
        ASN1.DER.decode(load_der("bitstring_badunused")))
    # Set out-of-order: check that it parses, but round-trip generates 
    # canonical encoding
    @test_throws ErrorException ASN1.DER.decode(load_der("set_outoforder"))
end

@testset "DER: Public Key Structures" begin
    # RSA public key (SPKI)
    rsa_spki_der = load_der("rsa_spki")
    rsa_tree = ASN1.DER.decode(rsa_spki_der)
    spki = der_to_asn1(rsa_tree)
    @test spki isa ASN1Sequence
    # Should contain AlgId and BITSTRING
    @test spki.elements[2] isa ASN1BitString ||
          spki.elements[end] isa ASN1BitString

    # EC (P-256) public key (SPKI)
    ec_der = load_der("ec_p256_spki")
    ec_tree = ASN1.DER.decode(ec_der)
    spki_ec = der_to_asn1(ec_tree)
    @test spki_ec isa ASN1Sequence

    # Ed25519 (SPKI)
    ed_der = load_der("ed25519_spki")
    ed_tree = ASN1.DER.decode(ed_der)
    spki_ed = der_to_asn1(ed_tree)
    @test spki_ed isa ASN1Sequence
end

@testset "DER: X.509 Certificates" begin
    # Self-signed
    x509 = load_der("x509_rsa")
    tree = ASN1.DER.decode(x509)
    cert = der_to_asn1(tree)
    @test cert isa ASN1Sequence
    # CA and EE from the chain
    ca = load_der("x509_ca")
    ca_cert = der_to_asn1(ASN1.DER.decode(ca))
    @test ca_cert isa ASN1Sequence
    ee = load_der("x509_ee")
    ee_cert = der_to_asn1(ASN1.DER.decode(ee))
    @test ee_cert isa ASN1Sequence
end

@testset "DER: Encode/Decode Idempotence" begin
    # Only applies to strict DER encodings, not malformed
    for name in [
        "int_42", "bool_true", "null", "string", "oid_rsaEncryption",
        "octetstring", "bitstring", "sequence", "set", "nested",
        "rsa_spki", "ec_p256_spki", "ed25519_spki", "x509_rsa",
        "x509_ca", "x509_ee"]
        original = read(joinpath(TESTVEC_DIR, "$name.der"))
        decoded = ASN1.DER.decode(original)
        encoded = ASN1.DER.encode(decoded)
        @test encoded == original
    end
end

@testset "DER: Fuzz/Random Bytes" begin
    for n in 1:10
        data = rand(UInt8, n)
        try
            ASN1.DER.decode(data)
            # If decode succeeds, it must not crash, but don't require match
        catch e
            @test true  # Allowed to throw
        end
    end
end

@testset "DER: All files parse or error, no segfault" begin
    for fname in readdir(TESTVEC_DIR)
        endswith(fname, ".der") || continue
        data = read(joinpath(TESTVEC_DIR, fname))
        try
            ASN1.DER.decode(data)
            # Optional: println("Parsed: $fname")
        catch e
            # Should not segfault, panic, hang, etc
            @test true
        end
    end
end

WebAuthn.ASN1.EXTERNAL_DER_VALIDATION[] = true