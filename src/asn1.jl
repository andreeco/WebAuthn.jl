"""
This code must be reviewed! Testing is not done properly yet (RFC) 
and I must check it myself too (more).
"""

module AbstractSyntaxNotationOne

"""
    EXTERNAL_DER_VALIDATION

If `true`, all DER input is strictly validated with an external crypto library 
(OpenSSL) and parsing is rejected unless it is a recognized public key 
structure. 

Disabling this is insecure!
"""
const EXTERNAL_DER_VALIDATION = Ref(true)

@warn "ASN1 is experimental!"

export ASN1Value, ASN1Integer, ASN1Boolean, ASN1String, ASN1OID,
    ASN1Null, ASN1OctetString, ASN1BitString, ASN1Unknown,
    ASN1Sequence, ASN1Set, ASN1Error, der_to_asn1, asn1_to_der

using Base64

module DERFirewall

using OpenSSL_jll
const libcrypto = OpenSSL_jll.libcrypto

function parse_evp_pkey(der::Vector{UInt8})
    GC.@preserve der begin
        # pointer to buffer pointer
        p = Ref{Ptr{UInt8}}(pointer(der))
        len = Clong(length(der))
        # EVP_PKEY **a
        key = ccall((:d2i_PUBKEY, libcrypto), Ptr{Cvoid},
            (Ref{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            Ref{Ptr{Cvoid}}(C_NULL), p, len)
        return key
    end
end

function parse_rsa_publickey(der::Vector{UInt8})
    GC.@preserve der begin
        p = Ref{Ptr{UInt8}}(pointer(der))
        len = Clong(length(der))
        # RSA **a
        key = ccall((:d2i_RSAPublicKey, libcrypto), Ptr{Cvoid},
            (Ref{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            Ref{Ptr{Cvoid}}(C_NULL), p, len)
        return key
    end
end

function openssl_get_error_msg()
    msgs = String[]
    while true
        err = ccall((:ERR_get_error, libcrypto), Culong, ())
        err == 0 && break
        buf = Vector{UInt8}(undef, 256)
        ccall((:ERR_error_string_n, libcrypto), Cvoid,
            (Culong, Ptr{UInt8}, Csize_t),
            err, pointer(buf), Csize_t(length(buf)))
        n = findfirst(==(0x00), buf)
        if n !== nothing && n > 1
            push!(msgs, String(view(buf, 1:n-1)))
        else
            push!(msgs, unsafe_string(pointer(buf)))
        end
    end
    return isempty(msgs) ? "" : join(msgs, "; ")
end

function _verify_der_strict(der::Vector{UInt8}; allow_ec=true,
    allow_rsa=true, allow_ed25519=true)
    # Clear OpenSSL error queue before parsing
    ccall((:ERR_clear_error, libcrypto), Cvoid, ())

    key = parse_evp_pkey(der)
    if key != C_NULL
        # TODO: check key type! See notes.
        ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), key)
        return true
    end

    # Strict key type filtering - not active. Implement if EVP_PKEY_id available.
    # ktype = ccall((:EVP_PKEY_id, libcrypto), Cint, (Ptr{Cvoid},), key)
    # if (ktype == 408 && allow_ec) || 
    # (ktype == 6 && allow_rsa) || 
    # (ktype == 1087 && allow_ed25519)
    #     ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), key)
    #     return true
    # else
    #     ccall((:EVP_PKEY_free, libcrypto), Cvoid, (Ptr{Cvoid},), key)
    #     throw(ErrorException("Key type not allowed: $ktype"))
    # end

    if allow_rsa
        rsa = parse_rsa_publickey(der)
        if rsa != C_NULL
            ccall((:RSA_free, libcrypto), Cvoid, (Ptr{Cvoid},), rsa)
            return true
        end
    end
    msg = openssl_get_error_msg()
    throw(ErrorException("Key parse failed: Not a 
    recognized SPKI or RSA raw public key; $msg"))
end

end # module
using .DERFirewall

module DER

export DERTree, decode, encode, decode_pem, encode_pem,
    UNIVERSAL, APPLICATION, CONTEXT, PRIVATE,
    TAG_BOOLEAN, TAG_INTEGER, TAG_BIT_STRING, TAG_OCTET_STRING,
    TAG_NULL, TAG_OBJECT_ID, TAG_SEQUENCE, TAG_SET,
    TAG_UTF8_STRING, TAG_PRINTABLE_STRING

using Base64

using ..AbstractSyntaxNotationOne

const UNIVERSAL = 0     # 0b00 Universal class
const APPLICATION = 1   # 0b01 Application class
const CONTEXT = 2       # 0b10 Context-specific class
const PRIVATE = 3       # 0b11 Private class

const TAG_BOOLEAN = 1            # 0x01 BOOLEAN
const TAG_INTEGER = 2            # 0x02 INTEGER
const TAG_BIT_STRING = 3         # 0x03 BIT STRING
const TAG_OCTET_STRING = 4       # 0x04 OCTET STRING
const TAG_NULL = 5               # 0x05 NULL
const TAG_OBJECT_ID = 6          # 0x06 OBJECT IDENTIFIER
const TAG_UTF8_STRING = 12       # 0x0C UTF8String
const TAG_SEQUENCE = 16          # 0x10 SEQUENCE
const TAG_SET = 17               # 0x11 SET
const TAG_PRINTABLE_STRING = 19  # 0x13 PrintableString

mutable struct DERTree
    tag::Int
    class::Int
    length::Int
    value::Union{Nothing,Vector{UInt8}}
    children::Vector{DERTree}
end

DERTree(tag::Int, class::Int, value::Vector{UInt8}) =
    DERTree(tag, class, length(value), value, DERTree[])
DERTree(tag::Int, class::Int, children::Vector{DERTree}) =
    DERTree(tag, class, 0, nothing, children)

const MAX_DER_LENGTH = 10^6
const MAX_LENGTH_NBYTES = 8
const MAX_TAG_NBYTES = 5
const MAX_NESTING_DEPTH = 128

function _parse_length(data::Vector{UInt8}, pos::Int)
    if pos > length(data)
        throw(ErrorException("DER parse error: truncated in length byte"))
    end
    first = data[pos]
    if first & 0x80 == 0
        len, pos2 = Int(first), pos + 1
    else
        nbytes = Int(first & 0x7F)
        if nbytes == 0
            throw(ErrorException("Indefinite length not allowed"))
        end
        if nbytes > MAX_LENGTH_NBYTES
            throw(ErrorException("Length field too large ($nbytes bytes)"))
        end
        if pos + nbytes > length(data)
            throw(ErrorException("DER parse error: truncated length bytes"))
        end
        if nbytes > 1 && data[pos+1] == 0x00
            throw(ErrorException(
                "DER forbids overlong (non-minimal) length encoding"))
        end
        len = 0
        max_safe = typemax(Int) >> 8
        for i = 1:nbytes
            if len > max_safe
                throw(ErrorException("Length encoding too large"))
            end
            len = (len << 8) | Int(data[pos+i])
        end
        if nbytes > 1 && len < (1 << (8 * (nbytes - 1)))
            throw(ErrorException("DER forbids non-minimal length"))
        end
        pos2 = pos + nbytes + 1
    end
    if len > MAX_DER_LENGTH
        throw(ErrorException("DER length $len exceeds max $MAX_DER_LENGTH"))
    end
    return len, pos2
end

function _decode_one(data::Vector{UInt8}, pos::Int, depth::Int=0)
    if depth > MAX_NESTING_DEPTH
        throw(ErrorException("DER parse error: 
        nesting depth > $MAX_NESTING_DEPTH"))
    end
    # Bounds check: is header present?
    if pos > length(data)
        throw(ErrorException("DER parse error: truncated in tag byte"))
    end
    tagbyte = data[pos]
    pos += 1
    class = (tagbyte >> 6) & 0x03
    isconst = (tagbyte & 0x20) != 0
    tag = tagbyte & 0x1F
    if tag == 0x1F
        tag = 0
        count_tag_bytes = 0
        while true
            if pos > length(data)
                throw(ErrorException(
                    "DER parse error: truncated in long-form tag"))
            end
            b = data[pos]
            pos += 1
            count_tag_bytes += 1
            if count_tag_bytes > MAX_TAG_NBYTES
                throw(ErrorException("Tag encoding too large"))
            end
            # check overflow before shift
            if tag > (typemax(Int) >> 7)
                throw(ErrorException("Tag value too large"))
            end
            tag = (tag << 7) | (Int(b) & 0x7F)
            if (b & 0x80) == 0
                break
            end
        end
    end
    if isconst && (tag == TAG_BIT_STRING || tag == TAG_OCTET_STRING)
        throw(ErrorException(
            "Constructed form forbidden for BIT/OCTET STRING in DER"))
    end

    # Bounds check: is there enough left for the length field (and value)?
    len, pos = _parse_length(data, pos)

    # Check there is enough data for the value or constructed body
    if pos + len - 1 > length(data)
        throw(ErrorException("DER parse error: value overruns buffer"))
    end

    if isconst || tag in (TAG_SEQUENCE, TAG_SET)
        pend = pos + len - 1
        children = DERTree[]
        while pos <= pend
            if pos > pend
                break
            end
            child, pos = _decode_one(data, pos, depth + 1)
            push!(children, child)
        end
        return DERTree(tag, class, len, nothing, children), pend + 1
    else
        val = data[pos:pos+len-1]
        return DERTree(tag, class, len, val, DERTree[]), pos + len
    end
end

function decode(data::Vector{UInt8})
    if AbstractSyntaxNotationOne.EXTERNAL_DER_VALIDATION[]
        AbstractSyntaxNotationOne.DERFirewall._verify_der_strict(data)
    end
    tree, pos = _decode_one(data, 1, 0)
    if pos <= length(data)
        throw(ErrorException("Extra data after root element"))
    end
    return tree
end

function _encode_length(len::Int)
    if len < 0x80
        return [UInt8(len)]
    end
    acc = UInt8[]
    tmp = len
    while tmp > 0
        pushfirst!(acc, UInt8(tmp & 0xFF))
        tmp >>= 8
    end
    return [UInt8(0x80 + length(acc)); acc...]
end

function _encode_one(node::DERTree)
    tagnum = node.tag
    classbits = UInt8((node.class << 6) & 0xC0)
    constructedbit = isempty(node.children) ? UInt8(0x00) : UInt8(0x20)
    out = UInt8[]
    if tagnum < 0x1F
        push!(out, UInt8(classbits | constructedbit | (UInt8(tagnum & 0x1F))))
    else
        push!(out, UInt8(classbits | constructedbit | 0x1F))
        # encode tagnum in base-128 big-endian groups
        parts = UInt8[]
        tmp = tagnum
        pushfirst!(parts, UInt8(tmp & 0x7F))
        tmp >>= 7
        while tmp > 0
            pushfirst!(parts, UInt8(0x80 | (tmp & 0x7F)))
            tmp >>= 7
        end
        append!(out, parts)
    end
    if isempty(node.children)
        append!(out, _encode_length(node.length))
        append!(out, node.value)
    else
        payload = UInt8[]
        for c in node.children
            append!(payload, _encode_one(c))
        end
        append!(out, _encode_length(length(payload)))
        append!(out, payload)
    end
    return out
end

function encode(tree::DERTree)
    bytes = _encode_one(tree)
    if AbstractSyntaxNotationOne.EXTERNAL_DER_VALIDATION[]
        AbstractSyntaxNotationOne.DERFirewall._verify_der_strict(bytes)
    end
    return bytes
end

function decode_pem(pem::String)
    m = match(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END ([A-Z ]+)-----"ms, pem)
    if m === nothing || m.captures[1] != m.captures[3]
        throw(ErrorException("PEM label mismatch"))
    end
    body = replace(m.captures[2], r"\s+" => "")
    if length(body) > 4 * (MAX_DER_LENGTH + 1024)
        throw(ErrorException("PEM body too large"))
    end
    return decode(Vector{UInt8}(base64decode(body)))
end

function encode_pem(tree::DERTree; label="ASN1")
    b64 = base64encode(encode(tree))
    chunks = [b64[i:min(i + 63, end)] for i = 1:64:length(b64)]
    return "-----BEGIN $label-----\n" * join(chunks, "\n") *
           "\n-----END $label-----\n"
end

function Base.show(io::IO, node::DERTree)
    if isempty(node.children)
        print(io, "DERTree(tag=$(node.tag),class=$(node.class),",
            "len=$(node.length),value=$(node.value))")
    else
        print(io, "DERTree(tag=$(node.tag),class=$(node.class),",
            "children=$(node.children))")
    end
end
end

using .DER

abstract type ASN1Value end
abstract type ASN1Primitive <: ASN1Value end
abstract type ASN1Constructed <: ASN1Value end

struct ASN1Error <: Exception
    msg::String
end
Base.showerror(io::IO, e::ASN1Error) = print(io, "ASN1Error: ", e.msg)

struct ASN1Integer <: ASN1Primitive
    value::BigInt
end
struct ASN1Boolean <: ASN1Primitive
    value::Bool
end
struct ASN1String <: ASN1Primitive
    str::String
    kind::Symbol
end
ASN1String(s::String) = ASN1String(s, :UTF8String)
ASN1String(kind::Symbol, s::String) = ASN1String(s, kind)

struct ASN1OID <: ASN1Primitive
    oid::Vector{Int}
end
struct ASN1Null <: ASN1Primitive end
struct ASN1OctetString <: ASN1Primitive
    bytes::Vector{UInt8}
end
struct ASN1BitString <: ASN1Primitive
    bits::BitVector
end

struct ASN1Unknown <: ASN1Primitive
    tag::Int
    class::Int
    raw::Vector{UInt8}
end

struct ASN1Sequence <: ASN1Constructed
    elements::Vector{ASN1Value}
end
struct ASN1Set <: ASN1Constructed
    elements::Vector{ASN1Value}
end

asn1_type(::Val{2}) = ASN1Integer
asn1_type(::Val{1}) = ASN1Boolean
asn1_type(::Val{3}) = ASN1BitString
asn1_type(::Val{4}) = ASN1OctetString
asn1_type(::Val{12}) = ASN1String
asn1_type(::Val{19}) = ASN1String
asn1_type(::Val{6}) = ASN1OID
asn1_type(::Val{5}) = ASN1Null
asn1_type(::Val{16}) = ASN1Sequence
asn1_type(::Val{17}) = ASN1Set
asn1_type(::Val{T}) where T = ASN1Unknown

function der_to_asn1(node::DER.DERTree)
    typ = asn1_type(Val(node.tag))
    decode_value(typ, node)
end

function decode_integer(bytes::Vector{UInt8})
    if isempty(bytes)
        throw(ASN1Error("Empty INTEGER"))
    end
    # Zero must be [0x00]
    if all(x -> x == 0x00, bytes) && length(bytes) > 1
        throw(ASN1Error("INTEGER zero must be [0x00] only"))
    end
    # Positive: first byte 0x00 only if 2nd has high bit
    if (bytes[1] == 0x00) && (length(bytes) > 1) && (bytes[2] & 0x80 == 0)
        throw(ASN1Error("INTEGER non-minimal DER encoding: redundant 0x00"))
    end
    # Negative: first byte 0xFF only if 2nd has high bit set
    if (bytes[1] == 0xFF) && (length(bytes) > 1) && (bytes[2] & 0x80 == 0x80)
        throw(ASN1Error("INTEGER non-minimal DER encoding: redundant 0xFF"))
    end
    n = BigInt(0)
    for b in bytes
        n = (n << 8) | b
    end
    if !isempty(bytes) && (bytes[1] & 0x80 != 0)
        n -= BigInt(1) << (8 * length(bytes))
    end
    n
end

_decode_oid(bytes::Vector{UInt8}) = begin
    if isempty(bytes)
        return Int[]
    end
    firstv = Int(bytes[1])
    out = [div(firstv, 40), mod(firstv, 40)]
    if out[1] > 2 || (out[1] < 2 && out[2] > 39)
        throw(ASN1Error("Invalid OID first two arcs"))
    end
    val = 0
    for b in bytes[2:end]
        val = (val << 7) | (b & 0x7f)
        if b & 0x80 == 0
            push!(out, val)
            val = 0
        end
    end
    out
end

function _is_printable_string(s::String)
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" *
              "0123456789 '()+,-./:=?"
    all(c -> c in allowed, s)
end

decode_value(::Type{ASN1Integer}, n::DER.DERTree) =
    ASN1Integer(decode_integer(n.value))
decode_value(::Type{ASN1Boolean}, n::DER.DERTree) = begin
    if length(n.value) != 1
        throw(ASN1Error("Invalid BOOLEAN length"))
    end
    b = n.value[1]
    if b == 0x00
        ASN1Boolean(false)
    elseif b == 0xff
        ASN1Boolean(true)
    else
        throw(ASN1Error("Invalid BOOLEAN encoding"))
    end
end
decode_value(::Type{ASN1String}, n::DER.DERTree) = begin
    kind = n.tag == DER.TAG_UTF8_STRING ? :UTF8String : :PrintableString
    s = String(n.value)
    if kind == :PrintableString && !_is_printable_string(s)
        throw(ASN1Error("Invalid PrintableString"))
    end
    ASN1String(s, kind)
end
decode_value(::Type{ASN1OID}, n::DER.DERTree) = ASN1OID(_decode_oid(n.value))
decode_value(::Type{ASN1Null}, ::DER.DERTree) = ASN1Null()
decode_value(::Type{ASN1OctetString}, n::DER.DERTree) =
    ASN1OctetString(n.value)
decode_value(::Type{ASN1BitString}, n::DER.DERTree) = begin
    if isempty(n.value)
        throw(ASN1Error("Empty BIT STRING"))
    end
    unused = n.value[1]
    if unused > 7
        throw(ASN1Error("Bad BIT STRING unused count"))
    end
    bitsbytes = n.value[2:end]
    if unused > 0 && !isempty(bitsbytes)
        mask = (1 << unused) - 1
        if bitsbytes[end] & mask != 0
            throw(ASN1Error("Bad BIT STRING padding"))
        end
    end
    bits = falses(length(bitsbytes) * 8 - unused)
    k = 1
    for (i, b) in enumerate(bitsbytes)
        for j in 7:-1:0
            if k <= length(bits)
                bits[k] = ((b >> j) & 1) == 1
                k += 1
            end
        end
    end
    ASN1BitString(bits)
end
decode_value(::Type{ASN1Sequence}, n::DER.DERTree) =
    ASN1Sequence([der_to_asn1(c) for c in n.children])

decode_value(::Type{ASN1Set}, n::DER.DERTree) =
    ASN1Set([der_to_asn1(c) for c in n.children])

decode_value(::Type{ASN1Unknown}, n::DER.DERTree) =
    ASN1Unknown(n.tag, n.class, n.value === nothing ? UInt8[] : n.value)

function asn1_to_der(x::ASN1Value)::DER.DERTree
    encode_value(x)
end

_encode_integer(n::BigInt) = begin
    neg = n < 0
    tmp = abs(n)
    bytes = UInt8[]
    while tmp > 0
        pushfirst!(bytes, UInt8(tmp & 0xff))
        tmp >>= 8
    end
    if isempty(bytes)
        bytes = [0x00]
    end
    if neg
        width = 8 * length(bytes)
        maxval = BigInt(1) << width
        val = maxval + n
        bytes = UInt8[]
        while val > 0
            pushfirst!(bytes, UInt8(val & 0xff))
            val >>= 8
        end
    elseif bytes[1] & 0x80 != 0
        bytes = [0x00; bytes]
    end
    bytes
end

_encode_oid(oid::Vector{Int}) = begin
    if length(oid) < 2
        throw(ASN1Error("OID needs 2+ parts"))
    end
    out = UInt8[(oid[1]*40+oid[2])]
    for v in oid[3:end]
        stack = UInt8[]
        tmp = v
        pushfirst!(stack, UInt8(tmp & 0x7f))
        tmp >>= 7
        while tmp > 0
            pushfirst!(stack, UInt8(0x80 | (tmp & 0x7f)))
            tmp >>= 7
        end
        append!(out, stack)
    end
    out
end

encode_value(x::ASN1Integer) =
    DER.DERTree(DER.TAG_INTEGER, DER.UNIVERSAL, _encode_integer(x.value))
encode_value(x::ASN1Boolean) =
    DER.DERTree(DER.TAG_BOOLEAN, DER.UNIVERSAL,
        [UInt8(x.value ? 0xff : 0x00)])
encode_value(x::ASN1String) = begin
    tag = x.kind == :UTF8String ? DER.TAG_UTF8_STRING : DER.TAG_PRINTABLE_STRING
    DER.DERTree(tag, DER.UNIVERSAL, Vector{UInt8}(x.str))
end
encode_value(x::ASN1OID) =
    DER.DERTree(DER.TAG_OBJECT_ID, DER.UNIVERSAL, _encode_oid(x.oid))
encode_value(::ASN1Null) =
    DER.DERTree(DER.TAG_NULL, DER.UNIVERSAL, UInt8[])
encode_value(x::ASN1OctetString) =
    DER.DERTree(DER.TAG_OCTET_STRING, DER.UNIVERSAL, x.bytes)
encode_value(x::ASN1BitString) = begin
    unused = (8 - (length(x.bits) % 8)) % 8
    bytes = UInt8[]
    cur = 0
    cnt = 0
    for b in x.bits
        cur = (cur << 1) | (b ? 1 : 0)
        cnt += 1
        if cnt % 8 == 0
            push!(bytes, UInt8(cur))
            cur = 0
        end
    end
    if unused > 0
        cur <<= unused
        push!(bytes, UInt8(cur))
    end
    DER.DERTree(DER.TAG_BIT_STRING, DER.UNIVERSAL, [UInt8(unused); bytes...])
end
encode_value(x::ASN1Sequence) =
    DER.DERTree(DER.TAG_SEQUENCE, DER.UNIVERSAL, [asn1_to_der(e) for e
                                                  in
                                                  x.elements])

function encode_value(x::ASN1Set)
    encoded_pairs = [(DER.encode(asn1_to_der(e)), asn1_to_der(e)) for
                     e in x.elements]
    sort!(encoded_pairs, by=p -> p[1])
    sorted_trees = [p[2] for p in encoded_pairs]
    return DER.DERTree(DER.TAG_SET, DER.UNIVERSAL, sorted_trees)
end

encode_value(x::ASN1Unknown) =
    DER.DERTree(x.tag, x.class, x.raw)

import Base: ==
==(a::ASN1Integer, b::ASN1Integer) = a.value == b.value
==(a::ASN1Boolean, b::ASN1Boolean) = a.value == b.value
==(a::ASN1String, b::ASN1String) =
    a.kind == b.kind && a.str == b.str
==(a::ASN1OID, b::ASN1OID) = a.oid == b.oid
==(a::ASN1OctetString, b::ASN1OctetString) = a.bytes == b.bytes
==(a::ASN1BitString, b::ASN1BitString) = a.bits == b.bits
==(a::ASN1Null, b::ASN1Null) = true
==(a::ASN1Sequence, b::ASN1Sequence) = a.elements == b.elements
==(a::ASN1Set, b::ASN1Set) = a.elements == b.elements
==(a::ASN1Unknown, b::ASN1Unknown) =
    a.tag == b.tag && a.class == b.class && a.raw == b.raw

import Base: convert

function convert(::Type{Vector{UInt8}}, bs::ASN1BitString)
    nbits = length(bs.bits)
    nbytes = (nbits + 7) ÷ 8   # correct calculation
    out = Vector{UInt8}(undef, nbytes)
    for i in 1:nbytes
        byte::UInt8 = 0
        for j in 0:7
            bit_index = (i - 1) * 8 + (j + 1)
            if bit_index <= nbits && bs.bits[bit_index]
                byte |= 0x80 >> j
            end
        end
        out[i] = byte
    end
    return out
end

end