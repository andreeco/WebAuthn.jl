using Test, WebAuthn
using .AbstractSyntaxNotationOne

AbstractSyntaxNotationOne.EXTERNAL_DER_VALIDATION[] = false

function parse_ec_pem_xy_native(pem::AbstractString)
    der = pem_to_der(pem)
    spki = AbstractSyntaxNotationOne.der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(der))
    if !(spki isa ASN1Sequence)
        throw(ArgumentError(
            "DER is not an ASN1Sequence (got $(typeof(spki)))"))
    end
    if length(spki.elements) < 2
        throw(ArgumentError("SubjectPublicKeyInfo missing elements"))
    end
    _, bitstr = spki.elements
    if !(bitstr isa ASN1BitString)
        throw(ArgumentError(
            "SubjectPublicKeyInfo does not contain ASN1BitString"))
    end
    rawbytes = convert(Vector{UInt8}, bitstr)
    if length(rawbytes) < 1 || rawbytes[1] != 0x04
        throw(ArgumentError(
            "Only uncompressed EC points supported (0x04 prefix needed)"))
    end
    if length(rawbytes) != 65
        throw(ArgumentError(
            "Expected 65-byte EC point, got $(length(rawbytes)) bytes"))
    end
    x = rawbytes[2:33]
    y = rawbytes[34:65]
    return x, y
end

function parse_rsa_pem_ne_native(pem::AbstractString)
    der = WebAuthn.pem_to_der(pem)
    spki = AbstractSyntaxNotationOne.der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(der))
    _, bitstr = spki.elements
    inner_bytes = convert(Vector{UInt8}, bitstr)
    tree, _ = AbstractSyntaxNotationOne.DER._decode_one(inner_bytes, 1, 0)
    n_node = tree.children[1]
    e_node = tree.children[2]
    return n_node.value, e_node.value
end

function parse_ed25519_pem_x_native(pem::AbstractString)
    der = pem_to_der(pem)
    spki = AbstractSyntaxNotationOne.der_to_asn1(
        AbstractSyntaxNotationOne.DER.decode(der))
    if length(spki.elements) < 2
        throw(ArgumentError("Ed25519 key ASN.1 structure missing elements"))
    end
    _, bitstr = spki.elements
    rawbytes = convert(Vector{UInt8}, bitstr)
    if length(rawbytes) != 32
        throw(ArgumentError(
            "Expected 32-byte Ed25519 key, got $(length(rawbytes)) bytes"))
    end
    return rawbytes
end

function normalize_for_crypto(integer::Vector{UInt8})
    # Strips a single leading 0x00 if present and second byte's highbit is set
    (length(integer) > 1 && integer[1] == 0x00 && integer[2] >= 0x80) ?
        integer[2:end] : integer
end

@testset "ASN.1 Native vs OpenSSL PEM cross-tests" begin
    @testset "EC P-256 SPKI" begin
        pem = load_vector("vectors_ec2_packed", "pubkey.pem")
        x_native, y_native = parse_ec_pem_xy_native(pem)
        x_ref, y_ref = parse_ec_pem_xy(pem)
        @test x_native == x_ref
        @test y_native == y_ref
    end
    @testset "RSA SPKI" begin
        pem = load_vector("keys", "rsa_spki.pem")
        n_native, e_native = parse_rsa_pem_ne_native(pem)
        n_ref, e_ref = parse_rsa_pem_ne(pem)
        @test normalize_for_crypto(n_native) == normalize_for_crypto(n_ref)
        @test e_native == e_ref
    end
    @testset "Ed25519 SPKI" begin
        pem = load_vector("vectors_ed25519_packed", "pubkey.pem")
        x_native = parse_ed25519_pem_x_native(pem)
        x_ref = parse_ed25519_pem_x(pem)
        @test x_native == x_ref
    end
end

@testset "ASN.1 Cross - Malformed PEMs" begin
    badpem = "-----BEGIN PUBLIC KEY-----\nZZZZZZZ\n-----END PUBLIC KEY-----"
    @test_throws Exception parse_ec_pem_xy_native(badpem)
end

AbstractSyntaxNotationOne.EXTERNAL_DER_VALIDATION[] = true