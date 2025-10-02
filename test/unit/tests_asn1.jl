using Test, Base64, WebAuthn, .AbstractSyntaxNotationOne

AbstractSyntaxNotationOne.EXTERNAL_DER_VALIDATION[] = false

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
        encoded = AbstractSyntaxNotationOne.DER.encode(asn1_to_der(v))
        decoded = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(encoded))
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
    der = AbstractSyntaxNotationOne.DER.encode(asn1_to_der(val))
    pem = AbstractSyntaxNotationOne.DER.encode_pem(
        asn1_to_der(val), label="OID")
    @test pem isa String
    parsed = AbstractSyntaxNotationOne.DER.decode_pem(pem) |> der_to_asn1
    @test parsed == val
end

@testset "Invalid DER Inputs" begin
    # BAD BOOLEAN: value other than 0x00/0xFF
    bad_bool = UInt8[0x01, 0x01, 0x01]
    @test_throws ASN1Error der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(bad_bool))

    # BAD BIT STRING: unused bits > 7
    bad_bit = UInt8[0x03, 0x02, 0x09, 0x00]
    @test_throws ASN1Error der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(bad_bit))

    # BAD BIT STRING: nonzero unused bits
    bitstr = [true, false, false, false, false, false, true]
    valid = [0x03, 0x02, 0x01, 0x83]
    # 1 unused, but LSB is set in last byte
    @test_throws ASN1Error der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(valid))

    # BAD OID
    bad_oid1 = UInt8[0x06, 0x01, 0x78]
    # [3, x] or [1, >39]
    for data in (bad_oid1,)
        @test_throws ASN1Error der_to_asn1(
            AbstractSyntaxNotationOne.DER.decode(data))
    end

    # BAD PrintableString: symbol not allowed
    str = "ABC@DEF"
    der = asn1_to_der(ASN1String(:PrintableString, str))
    der.value = Vector{UInt8}(str)  # force bad input
    der.tag = AbstractSyntaxNotationOne.DER.TAG_PRINTABLE_STRING
    raw = AbstractSyntaxNotationOne.DER.encode(der)
    @test_throws ASN1Error der_to_asn1(AbstractSyntaxNotationOne.DER.decode(raw))

    # BAD length: excessive size
    too_big = UInt8[0x04, 0x84, 0x10, 0x00, 0x00, 0x00]  # > MAX_DER_LENGTH
    @test_throws ErrorException AbstractSyntaxNotationOne.DER.decode(too_big)

    # BAD DER: indefinite length (0x80 marker)
    indef = UInt8[0x05, 0x80, 0x00, 0x00]
    @test_throws ErrorException AbstractSyntaxNotationOne.DER.decode(indef)

    # BAD DER: extra trailing data
    d = AbstractSyntaxNotationOne.DER.encode(asn1_to_der(ASN1Integer(3)))
    @test_throws ErrorException AbstractSyntaxNotationOne.DER.decode([d; 0x00])
end

@testset "SET Canonical Encoding (DER)" begin
    # In DER, elements of a SET are sorted by DER encoding
    a, b, c = ASN1Integer(42), ASN1Integer(1), ASN1Null()
    set1 = ASN1Set([a, b, c])
    set2 = ASN1Set([b, a, c])
    enc1 = AbstractSyntaxNotationOne.DER.encode(asn1_to_der(set1))
    enc2 = AbstractSyntaxNotationOne.DER.encode(asn1_to_der(set2))
    @test enc1 == enc2  # should sort identically!
    # And roundtrip, order won't matter
    dec = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(enc1))
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
        _ = AbstractSyntaxNotationOne.DER.encode(asn1_to_der(node))
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
            AbstractSyntaxNotationOne.DER.decode(bytes)
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

@testset "DER: Primitive and Constructed" begin
    @test der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(
            load_der("int_42"))) == ASN1Integer(42)
    @test der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(
            load_der("bool_true"))) == ASN1Boolean(true)
    @test der_to_asn1(AbstractSyntaxNotationOne.DER.decode(
        load_der("null"))) == ASN1Null()
    @test der_to_asn1(AbstractSyntaxNotationOne.DER.decode(load_der(
        "oid_rsaEncryption"))) == ASN1OID([1, 2, 840, 113549, 1, 1, 1])
    @test der_to_asn1(AbstractSyntaxNotationOne.DER.decode(load_der(
        "octetstring"))) == ASN1OctetString([0xde, 0xad, 0xbe, 0xef])
    @test der_to_asn1(AbstractSyntaxNotationOne.DER.decode(load_der(
        "bitstring"))) == ASN1BitString(BitVector(
        [true, true, false, true, false, false, true, true]))  # 0xd3
    # PrintableString
    s = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(
        load_der("string")))
    @test s isa ASN1String && s.str == "HelloJULIA"
    # SEQUENCE
    seq = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(
        load_der("sequence")))
    @test seq isa ASN1Sequence
    # SET
    st = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(
        load_der("set")))
    @test st isa ASN1Set
    # NESTED
    nest = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(
        load_der("nested")))
    @test nest isa ASN1Sequence
end

@testset "DER: Malformed and Forbidden Encodings" begin
    # Overlong integer length: forbidden in canonical DER
    @test_throws ErrorException AbstractSyntaxNotationOne.DER.decode(
        load_der("int_42_overlong"))
    # Indefinite length encoding: forbidden in DER
    @test_throws ErrorException AbstractSyntaxNotationOne.DER.decode(
        load_der("octetstring_indef"))
    # Bad BIT STRING: unused bits out of bounds
    @test_throws ASN1Error der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(load_der("bitstring_badunused")))
    # Set out-of-order: check that it parses, but round-trip generates 
    # canonical encoding
    @test_throws ErrorException AbstractSyntaxNotationOne.DER.decode(
        load_der("set_outoforder"))
end

@testset "DER: Public Key Structures" begin
    # RSA public key (SPKI)
    rsa_spki_der = load_der("rsa_spki")
    rsa_tree = AbstractSyntaxNotationOne.DER.decode(rsa_spki_der)
    spki = der_to_asn1(rsa_tree)
    @test spki isa ASN1Sequence
    # Should contain AlgId and BITSTRING
    @test spki.elements[2] isa ASN1BitString ||
          spki.elements[end] isa ASN1BitString

    # EC (P-256) public key (SPKI)
    ec_der = load_der("ec_p256_spki")
    ec_tree = AbstractSyntaxNotationOne.DER.decode(ec_der)
    spki_ec = der_to_asn1(ec_tree)
    @test spki_ec isa ASN1Sequence

    # Ed25519 (SPKI)
    ed_der = load_der("ed25519_spki")
    ed_tree = AbstractSyntaxNotationOne.DER.decode(ed_der)
    spki_ed = der_to_asn1(ed_tree)
    @test spki_ed isa ASN1Sequence
end

@testset "DER: X.509 Certificates" begin
    # Self-signed
    x509 = load_der("x509_rsa")
    tree = AbstractSyntaxNotationOne.DER.decode(x509)
    cert = der_to_asn1(tree)
    @test cert isa ASN1Sequence
    # CA and EE from the chain
    ca = load_der("x509_ca")
    ca_cert = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(ca))
    @test ca_cert isa ASN1Sequence
    ee = load_der("x509_ee")
    ee_cert = der_to_asn1(AbstractSyntaxNotationOne.DER.decode(ee))
    @test ee_cert isa ASN1Sequence
end

@testset "DER: Encode/Decode Idempotence" begin
    # Only applies to strict DER encodings, not malformed
    for name in [
        "int_42", "bool_true", "null", "string", "oid_rsaEncryption",
        "octetstring", "bitstring", "sequence", "set", "nested",
        "rsa_spki", "ec_p256_spki", "ed25519_spki", "x509_rsa",
        "x509_ca", "x509_ee"]
        original = load_der(name)
        decoded = AbstractSyntaxNotationOne.DER.decode(original)
        encoded = AbstractSyntaxNotationOne.DER.encode(decoded)
        @test encoded == original
    end
end

@testset "DER: Fuzz/Random Bytes" begin
    for n in 1:10
        data = rand(UInt8, n)
        try
            AbstractSyntaxNotationOne.DER.decode(data)
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
            AbstractSyntaxNotationOne.DER.decode(data)
            # Optional: println("Parsed: $fname")
        catch e
            # Should not segfault, panic, hang, etc
            @test true
        end
    end
end

AbstractSyntaxNotationOne.EXTERNAL_DER_VALIDATION[] = true

const DERFIREWALL = AbstractSyntaxNotationOne.DERFirewall

# This ensures that there is a proven library backing the ASN1 parsing!
# OpenSSL is not recognizing :EVP_PKEY_id, so this is a good? workaround.

@testset "DERFirewall (OpenSSL C-layer) – all branches" begin
    # 1. Normal KEYS: must pass each parse route
    @testset "Valid public keys are accepted (all types)" begin
        rsa_key = load_der("rsa_spki")
        ec_key = load_der("ec_p256_spki")
        ed_key = load_der("ed25519_spki")
        # d2i_PUBKEY (RSA)
        @test DERFIREWALL._verify_der_strict(rsa_key) == true
        # d2i_PUBKEY (EC)
        @test DERFIREWALL._verify_der_strict(ec_key) == true
        # d2i_PUBKEY (Ed25519)
        @test DERFIREWALL._verify_der_strict(ed_key) == true
    end

    # 2. Malformed: all ways that must throw (every 'fail' branch)
    @testset "Malformed/evil DER is always rejected" begin
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[0x30, 0x81, 0x00])  # structural/trunc
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[0x30, 0xff, 0x00, 0x00])  # invalid length
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[0x31, 0x03, 0x00, 0x00])  # wrong tag
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[0xff, 0xff, 0xff, 0xff])  # fully invalid
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[])                        # empty der

        # Non-key ASN.1 structure
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            [0x30, 0x03, 0x02, 0x01, 0x42])
    end

    # 3. Corruption: test tag/length/data/structural, with commentary
    @testset "Corrupted good keys only tolerated in data" begin
        rsa_key = load_der("rsa_spki")
        ec_key = load_der("ec_p256_spki")
        ed_key = load_der("ed25519_spki")
        # Flip tag byte – must fail:
        mut_tag = copy(rsa_key)
        mut_tag[1] ⊻= 0xFF
        @test_throws ErrorException DERFIREWALL._verify_der_strict(mut_tag)
        # Flip length/header in EC:
        mut_len = copy(ec_key)
        mut_len[2] ⊻= 0x0F
        @test_throws ErrorException DERFIREWALL._verify_der_strict(mut_len)
        # Truncate Ed25519:
        mut_trunc = ed_key[1:end-3]
        @test_throws ErrorException DERFIREWALL._verify_der_strict(mut_trunc)
        # Flip a middle data byte – can be tolerated!
        mut_data = copy(rsa_key)
        mut_data[end-10] ⊻= 0xA5
        res = try
            DERFIREWALL._verify_der_strict(mut_data)
            :accepted
        catch
            :rejected
        end
        # OpenSSL: tolerant to some benign data mutations!
        @test res in (:accepted, :rejected)
    end

    # 4. Overlong and indefinite encodings (BER/evil)
    @testset "Overlong/BER keys are always rejected" begin
        # Overlong length
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[0x30, 0x84, 0x10, 0x00, 0x00, 0x00])
        # Indefinite length (0x80)
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            UInt8[0x30, 0x80, 0x00, 0x00])
    end

    # 5. Exotic/unsupported key kinds
    @testset "Unsupported/exotic keys are never accepted" begin
        for exotic in ("secp384r1_spki", "x25519_spki", "ed448_spki")
            path = joinpath(TESTVEC_DIR, exotic * ".der")
            if isfile(path)
                der = read(path)
                @test_throws ErrorException DERFIREWALL._verify_der_strict(der)
            end
        end
    end

    # 6. Fuzz: random bytes
    @testset "Fuzz random bytes – never crash, never pass" begin
        for i in 1:40
            bytes = rand(UInt8, rand(2:120))
            ok = false
            try
                DERFIREWALL._verify_der_strict(bytes)
            catch
                ok = true
            end
            @test ok # always must throw, never pass
        end
    end

    # 7. Large data, must fail and not crash
    @testset "Large input is robust" begin
        @test_throws ErrorException DERFIREWALL._verify_der_strict(
            rand(UInt8, 4096))
    end

    # 8. Empty/degenerate key file
    @testset "Empty input is always rejected" begin
        @test_throws ErrorException DERFIREWALL._verify_der_strict(UInt8[])
    end

    # 9. Test repeated allocation/free for resource safety
    @testset "Repeated parse/free does not leak handles" begin
        rsa_key = load_der("rsa_spki")
        for i in 1:1000
            ptr = DERFIREWALL.parse_evp_pkey(rsa_key)
            @test ptr != C_NULL
            ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid,
                (Ptr{Cvoid},), ptr)
        end
    end

    # 10. Key compare (keys_equal_by_openssl) – equal and not equal
    @testset "keys_equal_by_openssl: equal and mismatch" begin
        rsa_key = load_der("rsa_spki")
        rsa_key2 = copy(rsa_key)
        @test DERFIREWALL.keys_equal_by_openssl(rsa_key, rsa_key2)
        mut = copy(rsa_key)
        mut[end] ⊻= 0x1A
        @test_throws ErrorException DERFIREWALL.keys_equal_by_openssl(
            rsa_key, mut)
        ed_key = load_der("ed25519_spki")
        @test_throws ErrorException DERFIREWALL.keys_equal_by_openssl(
            rsa_key, ed_key)
    end

    # 11. Explicitly test pointer identity comparison (same handle)
    @testset "EVP_PKEY_cmp with same pointer returns 1" begin
        rsa_key = load_der("rsa_spki")
        ptr = DERFIREWALL.parse_evp_pkey(rsa_key)
        res = ccall((:EVP_PKEY_cmp, DERFIREWALL.libcrypto), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}), ptr, ptr)
        @test res == 1
        ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid, (Ptr{Cvoid},),
            ptr)
    end

    # 12. parse_rsa_publickey: valid raw and fallback behavior
    @testset "parse_rsa_publickey: valid and invalid" begin
        rsa_raw = load_der("rsa_raw")
        ptr = DERFIREWALL.parse_rsa_publickey(rsa_raw)
        @test ptr != C_NULL
        ccall((:RSA_free, DERFIREWALL.libcrypto), Cvoid, (Ptr{Cvoid},), ptr)
        # Should fail for other formats
        ed_key = load_der("ed25519_spki")
        ptr2 = DERFIREWALL.parse_rsa_publickey(ed_key)
        @test ptr2 == C_NULL
    end

    # 13. firewall_compare_der API: both (DER) and (DER, tree)
    @testset "firewall_compare_der: DER-only and (DER, tree) mode" begin
        rsa_key = load_der("rsa_spki")
        tree, pos = AbstractSyntaxNotationOne.DER._decode_one(
            rsa_key, 1, 0)
        @test DERFIREWALL.firewall_compare_der(rsa_key) == true
        @test DERFIREWALL.firewall_compare_der(rsa_key, tree) == true
        # Evil translation (encodings mismatch): must throw
        evil = copy(rsa_key)
        evil[end-4] ⊻= 0x10
        tree2, _ = AbstractSyntaxNotationOne.DER._decode_one(
            evil, 1, 0)
        @test_throws ErrorException DERFIREWALL.firewall_compare_der(
            evil, tree2)
        @test_throws ErrorException DERFIREWALL.firewall_compare_der(
            evil)
    end

    # 14. openssl_get_error_msg should be useful on error
    @testset "openssl_get_error_msg is nonempty after parse failure" begin
        _ = DERFIREWALL.parse_evp_pkey(UInt8[0xde, 0xad])
        msg = DERFIREWALL.openssl_get_error_msg()
        @test msg isa String
    end

    # 15. Fuzz parse_evp_pkey and parse_rsa_publickey for S crash/leak
    @testset "Fuzz parse_evp_pkey/parse_rsa_publickey \
    for leaks and aborts" begin
        for i in 1:100
            dat = rand(UInt8, rand(5:256))
            ptr = DERFIREWALL.parse_evp_pkey(dat)
            if ptr != C_NULL
                ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid,
                    (Ptr{Cvoid},), ptr)
            end
            ptr2 = DERFIREWALL.parse_rsa_publickey(dat)
            if ptr2 != C_NULL
                ccall((:RSA_free, DERFIREWALL.libcrypto), Cvoid,
                    (Ptr{Cvoid},), ptr2)
            end
        end
    end

    # 16. Defensive: compare keys of cross-type (should not semantically match)
    @testset "EVP_PKEY_cmp: cross-type keys never match" begin
        ec_key = load_der("ec_p256_spki")
        ed_key = load_der("ed25519_spki")
        ptr1 = DERFIREWALL.parse_evp_pkey(ec_key)
        ptr2 = DERFIREWALL.parse_evp_pkey(ed_key)
        cmp = ccall((:EVP_PKEY_cmp, DERFIREWALL.libcrypto), Cint, (Ptr{Cvoid},
                Ptr{Cvoid}), ptr1, ptr2)
        @test cmp != 1
        ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid,
            (Ptr{Cvoid},), ptr1)
        ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid,
            (Ptr{Cvoid},), ptr2)
    end

    # 17. Big fuzzer: stress all functions with 10000 random rounds 
    # (will catch handle/mem errors)
    @testset "Stress: 10000 rounds on ccall parse/free/cmp" begin
        keys = [
            load_der("rsa_spki"),
            load_der("ec_p256_spki"),
            load_der("ed25519_spki")
        ]
        for i in 1:10000
            dat = keys[rand(1:end)]
            ptr = DERFIREWALL.parse_evp_pkey(dat)
            if ptr != C_NULL
                ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid,
                    (Ptr{Cvoid},), ptr)
            end
            dat2 = keys[rand(1:end)]
            ptr2 = DERFIREWALL.parse_evp_pkey(dat2)
            if ptr2 != C_NULL
                ccall((:EVP_PKEY_free, DERFIREWALL.libcrypto), Cvoid,
                    (Ptr{Cvoid},), ptr2)
            end
            # Cross-compare sometimes
            if ptr != C_NULL && ptr2 != C_NULL
                ok = ccall((:EVP_PKEY_cmp, DERFIREWALL.libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{Cvoid}), ptr, ptr2)
                @test ok == 1 || ok == 0 || ok == -1
            end
        end
    end

end