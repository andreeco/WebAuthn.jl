export EC2PublicKey, RSAPublicKey, OKPPublicKey, WebAuthnPublicKey
export cose_key_parse, cose_key_to_pem

using WebAuthn.ASN1

"""
    abstract type WebAuthnPublicKey

Abstract supertype for all WebAuthn public key structs.
"""
abstract type WebAuthnPublicKey end

"""
    struct EC2PublicKey

Represent a COSE kty=2 EC2 public key (P-256/ES256).

Fields:
- x::Vector{UInt8}  # x coordinate
- y::Vector{UInt8}  # y coordinate
- alg::Int          # COSE alg, usually -7
- crv::Int          # COSE curve, usually 1 (P-256)

See also: [`RSAPublicKey`](@ref) and [`OKPPublicKey`](@ref).
"""
struct EC2PublicKey <: WebAuthnPublicKey
    x::Vector{UInt8}
    y::Vector{UInt8}
    alg::Int
    crv::Int
end

"""
    struct RSAPublicKey

Represent a COSE kty=3 RSA public key.

Fields:
- n::Vector{UInt8}  # modulus
- e::Vector{UInt8}  # exponent
- alg::Int          # COSE alg, usually -257

See also: [`EC2PublicKey`](@ref) and [`OKPPublicKey`](@ref).
"""
struct RSAPublicKey <: WebAuthnPublicKey
    n::Vector{UInt8}
    e::Vector{UInt8}
    alg::Int
end

"""
    struct OKPPublicKey

Represent a COSE kty=1 OKP public key (Ed25519).

Fields:
- x::Vector{UInt8}  # public key bytes
- alg::Int          # COSE alg, usually -8
- crv::Int          # COSE curve ID, usually 6

See also: [`EC2PublicKey`](@ref) and [`RSAPublicKey`](@ref).
"""
struct OKPPublicKey <: WebAuthnPublicKey
    x::Vector{UInt8}
    alg::Int
    crv::Int
end

"""
    cose_key_parse(cose::Dict)::WebAuthnPublicKey

Parse a COSE_Key dictionary to the appropriate public key struct.

# Examples
```jldoctests
julia> using WebAuthn

julia> cose = Dict(1=>2, 3=>-7, -1=>1, -2=>rand(UInt8,32), -3=>rand(UInt8,32));

julia> key = cose_key_parse(cose);
```

See also: [`EC2PublicKey`](@ref), [`RSAPublicKey`](@ref) and 
[`OKPPublicKey`](@ref).
"""
function cose_key_parse(cose::Dict)
    kty = cose[1]
    if kty == 2
        EC2PublicKey(cose[-2], cose[-3], cose[3], cose[-1])
    elseif kty == 3
        RSAPublicKey(cose[-1], cose[-2], cose[3])
    elseif kty == 1
        crv, alg, x = cose[-1], cose[3], cose[-2]
        crv == 6 && alg == -8 || error("Only Ed25519 (crv=6, alg=-8) supported")
        OKPPublicKey(x, alg, crv)
    else
        error("Unsupported COSE kty: $kty")
    end
end

"""
    cose_key_to_pem(key::WebAuthnPublicKey)::String

Convert a WebAuthn public key struct to PEM SubjectPublicKeyInfo string.

Creates a standard PEM format public key from a parsed WebAuthn/COSE public key
(e.g., `EC2PublicKey`, `RSAPublicKey`, or `OKPPublicKey`) for use with external
cryptographic libraries.

# Examples

```julia
julia> using WebAuthn

julia> key = EC2PublicKey(rand(UInt8,32), rand(UInt8,32), -7, 1);

julia> pem = cose_key_to_pem(key);
```

See also: [`cose_key_parse`](@ref).
"""
function cose_key_to_pem(key::WebAuthnPublicKey) end

function cose_key_to_pem(key::EC2PublicKey)
    pub = vcat(UInt8(0x04), key.x, key.y)
    asn1 = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
        0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03,
        0x01, 0x07, 0x03, 0x42, 0x00]
    der = vcat(asn1, pub)
    enc = base64encode(der)
    return "-----BEGIN PUBLIC KEY-----\n" *
           join([enc[i:min(i + 63, end)] for i = 1:64:length(enc)], "\n") *
           "\n-----END PUBLIC KEY-----\n"
end

function cose_key_to_pem(key::RSAPublicKey)
    function asn1_len(n)
        n < 128 ? UInt8[n] : vcat(UInt8(0x80 + length(digits(n, base=256))),
            UInt8.(reverse(digits(n, base=256))))
    end
    function der_integer(bytes)
        b = collect(bytes)
        b = isempty(b) ? UInt8[0] : b[1] > 0x7f ? vcat(0x00, b) : b
        vcat(0x02, asn1_len(length(b)), b)
    end
    pkseq_inner = vcat(der_integer(key.n), der_integer(key.e))
    pkseq = vcat(0x30, asn1_len(length(pkseq_inner)), pkseq_inner)
    pk_bs = vcat(0x03, asn1_len(length(pkseq) + 1), 0x00, pkseq)
    algid = UInt8[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
    body = vcat(algid, pk_bs)
    der = vcat(0x30, asn1_len(length(body)), body)
    enc = base64encode(der)
    return "-----BEGIN PUBLIC KEY-----\n" *
           join([enc[i:min(i + 63, end)] for i = 1:64:length(enc)], "\n") *
           "\n-----END PUBLIC KEY-----\n"
end

function cose_key_to_pem(key::OKPPublicKey)
    algid = UInt8[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]
    L = 1 + length(key.x)
    bitstr = vcat(0x03, L < 128 ? UInt8[L] : UInt8[0x81, L], 0x00, key.x)
    der = vcat(0x30, length(algid) + length(bitstr) < 128 ?
                     UInt8[length(algid)+length(bitstr)] : UInt8[0x81,
            length(algid)+length(bitstr)], algid, bitstr)
    enc = base64encode(der)
    return "-----BEGIN PUBLIC KEY-----\n" *
           join([enc[i:min(i + 63, end)] for i = 1:64:length(enc)], "\n") *
           "\n-----END PUBLIC KEY-----\n"
end

"""
    der_to_pem(derbytes::Vector{UInt8}, label::String = "CERTIFICATE")::String

Convert DER-encoded bytes to a PEM string with the specified label.

Formats binary DER data as a PEM-encoded string, splitting base64 lines to 64
characters and adding header and footer lines for the given type.

# Examples

```jldoctests
julia> using WebAuthn

julia> pem = WebAuthn.der_to_pem(rand(UInt8, 90), "PUBLIC KEY");
```

See also: [`cose_key_to_pem`](@ref).
"""
function der_to_pem(derbytes::Vector{UInt8}, label::String="CERTIFICATE")
    b64 = base64encode(derbytes)
    lines = ["-----BEGIN $label-----"]
    for i = 1:64:length(b64)
        push!(lines, b64[i:min(i+63, end)])
    end
    push!(lines, "-----END $label-----\n")
    join(lines, "\n")
end

"""
    extract_pubkey_pem_from_der(der::Vector{UInt8})::String

Extract a PEM-encoded EC public key from a DER-encoded X.509 certificate.

Searches the provided DER bytes for a known EC OID and extracts the embedded
public key, returning it as a PEM-encoded `SubjectPublicKeyInfo` suitable for
cryptographic libraries.

# Examples

```jldoctest
julia> using WebAuthn

julia> der = [
           0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
           0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,
           0x04,0xac,0x21,0x45,0xb3,0x77,0x1d,0xdd,0xab,0xbd,0x1c,0x34,0x5e,
           0xed,0x9d,0x6a,0x81,0xd9,0x32,0x42,0xe0,0xaf,0xf4,0x77,0x07,0xf0,
           0x65,0x64,0x69,0xae,0x95,0x50,0xfe,0x86,0x21,0xba,0xcf,0xb5,0x43,
           0xaf,0x90,0xe2,0xda,0xf4,0x2f,0x9f,0x9b,0x71,0x09,0x55,0x7a,0x53,
           0xc3,0x63,0x1e,0xb9,0xa9,0x3f,0xfb,0x66,0x32,0xfa,0x3a,0x49,0x01,
           0x01 ];

julia> pem = WebAuthn.extract_pubkey_pem_from_der(der);
```

See also: [`cose_key_to_pem`](@ref) and [`der_to_pem`](@ref).
"""
function extract_pubkey_pem_from_der(der::Vector{UInt8})
    oid = UInt8[0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01]
    oid_idx = findfirst(i->all(j->der[i+j-1]==oid[j],1:length(oid)), 
    1:length(der)-length(oid)+1)
    oid_idx === nothing && error("EC OID not found")
    idx = oid_idx + length(oid)
    while idx <= length(der) && der[idx] != 0x03
        idx += 1
    end
    lenbyte = der[idx+1]
    off = 2
    if lenbyte & 0x80 == 0x80
        lenlen = lenbyte & 0x7f
        bitstr_len = 0
        for i = 1:lenlen
            bitstr_len = (bitstr_len << 8) | der[idx+1+i]
        end
        off += lenlen
    else
        bitstr_len = lenbyte
    end
    unused = der[idx+off]
    off += 1
    # Try offsets for robustness
    for trial in 0:9
        ptry = der[idx+off+trial : min(length(der), idx+off+trial+64)]
        if length(ptry) == 65 && ptry[1] == 0x04
            pubkey = ptry
            spki_prefix = UInt8[
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 
                0x3D, 0x02, 0x01,
                0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 
                0x03, 0x42, 0x00 ]
            der_pk = vcat(spki_prefix, pubkey)
            b64 = base64encode(der_pk)
            lines = ["-----BEGIN PUBLIC KEY-----"]
            for i = 1:64:length(b64)
                push!(lines, b64[i:min(i+63, end)])
            end
            push!(lines, "-----END PUBLIC KEY-----\n")
            return join(lines, "\n")
        end
    end
    error("Could not find EC2 public key in DER")
end

function extract_pubkey_from_der_raw(der::Vector{UInt8})
    # Re-wrap in PEM and use existing parser:
    pem = WebAuthn.der_to_pem(der, "PUBLIC KEY")
    x, y = WebAuthn.parse_ec_pem_xy(pem)
    WebAuthn.EC2PublicKey(x, y, -7, 1)
end

export pem_to_der, parse_ec_pem_xy, parse_rsa_pem_ne, parse_ed25519_pem_x

"""
    pem_to_der(pem::AbstractString)::Vector{UInt8}

Decode a PEM-formatted string (e.g., a PEM public key or certificate) 
to a DER-encoded byte vector.

Strips header/footer and whitespace, decodes the enclosed base64.

## Example

```jldoctest
julia> using WebAuthn

julia> pem = \"\"\"
       -----BEGIN PUBLIC KEY-----
       MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK4CWBHImRgAVPXrmUD7VhNFW1sUs
       GI17tvaN6KEkBukdOj8cXnZSnhFuPrf8ajP8KrRoYiZqHVFy8zyrPJzFnw==
       -----END PUBLIC KEY-----
       \"\"\";

julia> der = WebAuthn.pem_to_der(pem);
```
"""
function pem_to_der(pem::AbstractString)
    b64 = match(r"-----BEGIN [A-Z ]+-----(.*?)-----END [A-Z ]+-----"ms, pem)
    b64 === nothing && error("PEM parse error")
    base64decode(replace(b64.captures[1], r"\s+" => ""))
end

"""
    parse_ec_pem_xy(pem::AbstractString)

Extract XY EC coordinates from a PEM/SPKI P-256 public key.

Parses a PEM-encoded (or plain DER) SubjectPublicKeyInfo containing a 
P-256 (secp256r1) uncompressed EC public key, as produced for WebAuthn and 
most browsers or OpenSSL tools. Returns X and Y coordinates of the EC point, 
each as a 32-byte vector.

Handles both short- and long-form DER length encodings, and scans all 
BIT STRING tags for an uncompressed point (0x04 prefix, 65 bytes total). 
Raises an error if not found.

# Example

```jldoctest
julia> using WebAuthn

julia> pem = \"\"\"
       -----BEGIN PUBLIC KEY-----
       MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK4CWBHImRgAVPXrmUD7VhNFW1sUs
       GI17tvaN6KEkBukdOj8cXnZSnhFuPrf8ajP8KrRoYiZqHVFy8zyrPJzFnw==
       -----END PUBLIC KEY-----
       \"\"\";

julia> x, y = parse_ec_pem_xy(pem);

julia> length(x), length(y)
(32, 32)
```
See also: [`pem_to_der`](@ref), [`asn1_parse_length`](@ref), 
[`parse_rsa_pem_ne`](@ref) and [`parse_ed25519_pem_x`](@ref).
"""
function parse_ec_pem_xy(pem::AbstractString)
    der  = pem_to_der(pem)
    spki = ASN1.der_to_asn1(ASN1.DER.decode(der))
    @assert spki isa ASN1Sequence

    _, bitstr = spki.elements
    @assert bitstr isa ASN1BitString

    rawbytes = convert(Vector{UInt8}, bitstr)

    @assert rawbytes[1] == 0x04 "Only uncompressed EC points supported"
    @assert length(rawbytes) == 65 "Expected 65-byte EC point"

    x = rawbytes[2:33]
    y = rawbytes[34:65]
    return x, y
end

"""
    parse_rsa_pem_ne(pem::AbstractString)

Extract the modulus (n) and exponent (e) from an RSA public key (PEM/SPKI).

Reads a PEM-encoded RSA SubjectPublicKeyInfo (as produced by OpenSSL, 
browser tools, etc.) and returns the modulus and exponent as byte vectors 
suitable for cryptographic use.

Raises an error if the ASN.1 structure is unexpected or unsupported.

# Example

```jldoctest
julia> using WebAuthn

julia> pem = \"\"\"
       -----BEGIN PUBLIC KEY-----
       MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2auHrQvvpQv/DI1wQAmd
       YCUYzOr8hWU2rMtDEae/p5Cu5pyNJRdv7DjOdOeWeWq1rA/Od/GY/HYazst1lWMC
       XjiW3nf0yV1jHoXl9Dc1wFTxl7EKrykK2EsijB8f93f4scxEalIyfjauXC6hIPi4
       /yWGS8cJOuj35ac/7N6GrUMIdzCj0qumTrUhRkmsJo2HtGm3dKkEZxHnL7fs/hln
       wwVOl2rqH0EcaVBSZwvjuEt6EfVMhqINp9FhRaIq5gx0ZpBR6OpFPM5oXrtMgsKO
       vIdZK7yZPcKw0JLmymZMi5gjgGVTX48YHoM8Mi6KtB4k2Rbp3Ouqc56odpLx2K2S
       cwIDAQAB
       -----END PUBLIC KEY-----
       \"\"\";

julia> n, e = parse_rsa_pem_ne(pem);

julia> length(n) > 200 && e == UInt8[0x01, 0x00, 0x01]
true
```
See also: [`pem_to_der`](@ref), [`asn1_parse_length`](@ref) and
[`parse_ec_pem_xy`](@ref).
"""
function parse_rsa_pem_ne(pem::AbstractString)
    der  = pem_to_der(pem)
    spki = ASN1.der_to_asn1(ASN1.DER.decode(der))
    _, bitstr = spki.elements

    inner_bytes = convert(Vector{UInt8}, bitstr)
    inner = ASN1.der_to_asn1(ASN1.DER.decode(inner_bytes))
    n_asn1, e_asn1 = inner.elements

    # Convert BigInt to big‑endian bytes
    bigint_to_bytes(b::BigInt) = begin
        v = b; v < 0 && error("Negative modulus/exponent not allowed")
        out = UInt8[]
        while v > 0
            pushfirst!(out, UInt8(v & 0xff))
            v >>= 8
        end
        isempty(out) && push!(out, 0x00)
        out
    end
    return bigint_to_bytes(n_asn1.value), bigint_to_bytes(e_asn1.value)
end

"""
    parse_ed25519_pem_x(pem::AbstractString)::x::Vector{UInt8}

Extract the x-coordinate (32 bytes) from an Ed25519 public key (PEM/SPKI).

Parses a PEM-encoded Ed25519 SubjectPublicKeyInfo as generated by OpenSSL or Python
and returns the 32-byte raw public key (`x`). This is useful for verifying 
Ed25519 signatures.

# Example

```jldoctest
julia> using WebAuthn

julia> pem = \"\"\"
       -----BEGIN PUBLIC KEY-----
       MCowBQYDK2VwAyEAoi3rnmJUD+qXNlp2pBkQWpXCUUjccW+6Ue5r0QDPF94=
       -----END PUBLIC KEY-----
       \"\"\";

julia> x = parse_ed25519_pem_x(pem);

julia> length(x)
32
```
See also: [`pem_to_der`](@ref), [`asn1_parse_length`](@ref) and 
[`parse_ec_pem_xy`](@ref).
"""
function parse_ed25519_pem_x(pem::AbstractString)
    der  = pem_to_der(pem)
    spki = ASN1.der_to_asn1(ASN1.DER.decode(der))
    _, bitstr = spki.elements
    rawbytes = convert(Vector{UInt8}, bitstr)
    @assert length(rawbytes) == 32
    return rawbytes
end