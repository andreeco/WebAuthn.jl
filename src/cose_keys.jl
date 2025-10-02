export EC2PublicKey, RSAPublicKey, OKPPublicKey, WebAuthnPublicKey
export cose_key_parse, cose_key_to_pem

using OpenSSL_jll

#using WebAuthn.AbstractSyntaxNotationOne


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

julia> x = UInt8[0x2b, 0x80, 0x96, 0x04, 0x72, 0x26, 0x46, 0x00, 0x15, 0x3d, 
                 0x7a, 0xe6, 0x50, 0x3e, 0xd5, 0x84, 0xd1, 0x56, 0xd6, 0xc5, 
                 0x2c, 0x18, 0x8d, 0x7b, 0xb6, 0xf6, 0x8d, 0xe8, 0xa1, 0x24, 
                 0x06, 0xe9];

julia> y = UInt8[0x1d, 0x3a, 0x3f, 0x1c, 0x5e, 0x76, 0x52, 0x9e, 0x11, 0x6e, 
                 0x3e, 0xb7, 0xfc, 0x6a, 0x33, 0xfc, 0x2a, 0xb4, 0x68, 0x62, 
                 0x26, 0x6a, 0x1d, 0x51, 0x72, 0xf3, 0x3c, 0xab, 0x3c, 0x9c, 
                 0xc5, 0x9f];

julia> cose = Dict(1=>2, 3=>-7, -1=>1, -2=>x, -3=>y);

julia> key = cose_key_parse(cose);

julia> key isa WebAuthn.EC2PublicKey
true
```

See also: [`EC2PublicKey`](@ref), [`RSAPublicKey`](@ref) and 
[`OKPPublicKey`](@ref).
"""
function cose_key_parse(cose::Dict)
    kty = cose[1]
    if kty == 2
        x = cose[-2]; y = cose[-3]; alg = cose[3]; crv = cose[-1]
        key = EC2PublicKey(x, y, alg, crv)

        # OpenSSL validation: try to serialize and load
        pem = cose_key_to_pem(key)
        try
            # Try to load via OpenSSL, error if invalid
            parse_ec_pem_xy(pem)
        catch e
            error("Invalid EC2 public key (OpenSSL could not parse): $e")
        end
        return key

    elseif kty == 3
        n = cose[-1]; e = cose[-2]; alg = cose[3]
        key = RSAPublicKey(n, e, alg)

        pem = cose_key_to_pem(key)
        try
            parse_rsa_pem_ne(pem)
        catch e
            error("Invalid RSA public key (OpenSSL could not parse): $e")
        end
        return key

    elseif kty == 1
        crv, alg, x = cose[-1], cose[3], cose[-2]
        crv == 6 && alg == -8 || error("Only Ed25519 (crv=6, alg=-8) supported")
        key = OKPPublicKey(x, alg, crv)

        pem = cose_key_to_pem(key)
        try
            parse_ed25519_pem_x(pem)
        catch e
            error("Invalid Ed25519 public key (OpenSSL could not parse): $e")
        end
        return key

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
    length(key.x) == 32 || error("EC2 x must be 32 bytes")
    length(key.y) == 32 || error("EC2 y must be 32 bytes")

    x = key.x
    y = key.y
    NID_P256 = 415

    ec_key = ccall((:EC_KEY_new_by_curve_name, OpenSSL_jll.libcrypto),
                   Ptr{Cvoid}, (Cint,), NID_P256)
    ec_key == C_NULL && error("OpenSSL: Failed to allocate EC_KEY")

    pk = nothing
    GC.@preserve x y begin
        bn_x = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(x), 32, C_NULL)
        bn_y = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(y), 32, C_NULL)
        try
            ok = ccall((:EC_KEY_set_public_key_affine_coordinates, 
            OpenSSL_jll.libcrypto),
                Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                ec_key, bn_x, bn_y)
            ok == 1 || error("OpenSSL: Failed to set EC_KEY coordinates")
            evp_key = ccall((:EVP_PKEY_new, OpenSSL_jll.libcrypto), 
            Ptr{Cvoid}, ())
            ccall((:EVP_PKEY_set1_EC_KEY, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}), evp_key, ec_key)
            buf_ptr = Ref{Ptr{UInt8}}()
            len = ccall((:i2d_PUBKEY, OpenSSL_jll.libcrypto), Cint,
                        (Ptr{Cvoid}, Ref{Ptr{UInt8}}), evp_key, buf_ptr)
            len <= 0 && error("OpenSSL: Could not encode EC public key")
            der = unsafe_wrap(Array, buf_ptr[], len; own=true)
            pk = der_to_pem(der, "PUBLIC KEY")
            ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid, 
            (Ptr{Cvoid},), evp_key)
        finally
            ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), bn_x)
            ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), bn_y)
            ccall((:EC_KEY_free, OpenSSL_jll.libcrypto), Cvoid, 
            (Ptr{Cvoid},), ec_key)
        end
    end
    return pk
end

function cose_key_to_pem(key::RSAPublicKey)
    # Validate key field lengths (minimal)
    isempty(key.n) && error("RSA modulus (n) must not be empty")
    isempty(key.e) && error("RSA exponent (e) must not be empty")
    # Create BIGNUMs for n, e
    rsa = ccall((:RSA_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, ())
    bn_n = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
        (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(key.n), length(key.n), C_NULL)
    bn_e = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
        (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(key.e), length(key.e), C_NULL)
    try
        ok = ccall((:RSA_set0_key, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            rsa, bn_n, bn_e, C_NULL)
        ok == 1 || error("OpenSSL: Failed RSA_set0_key")
        bn_n = bn_e = C_NULL # Ownership to RSA

        # Wrap in EVP_PKEY for DER export
        evp_key = ccall((:EVP_PKEY_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, ())
        ccall((:EVP_PKEY_set1_RSA, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}), evp_key, rsa)
        buf_ptr = Ref{Ptr{UInt8}}()
        len = ccall((:i2d_PUBKEY, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ref{Ptr{UInt8}}), evp_key, buf_ptr)
        len <= 0 && error("OpenSSL: Could not encode RSA public key")
        der = unsafe_wrap(Array, buf_ptr[], len; own=true)
        pem = der_to_pem(der, "PUBLIC KEY")
        # Free
        ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid, 
        (Ptr{Cvoid},), evp_key)
        return pem
    finally
        ccall((:RSA_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), rsa)
    end
end

function cose_key_to_pem(key::OKPPublicKey)
    length(key.x) == 32 || error("Ed25519 x must be 32 bytes")
    # Create EVP_PKEY* from raw Ed25519 public key
    evp_key = ccall((:EVP_PKEY_new_raw_public_key, OpenSSL_jll.libcrypto),
                    Ptr{Cvoid},
                    (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                    1087, # NID_ED25519
                    C_NULL, # no engine
                    pointer(key.x), Csize_t(length(key.x)))
    evp_key == C_NULL && error("OpenSSL: Failed to create Ed25519 key")
    pem = nothing
    try
        buf_ptr = Ref{Ptr{UInt8}}()
        len = ccall((:i2d_PUBKEY, OpenSSL_jll.libcrypto), Cint,
            (Ptr{Cvoid}, Ref{Ptr{UInt8}}), evp_key, buf_ptr)
        len <= 0 && error("OpenSSL: Could not encode Ed25519 public key")
        der = unsafe_wrap(Array, buf_ptr[], len; own=true)
        pem = der_to_pem(der, "PUBLIC KEY")
    finally
        ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid,
              (Ptr{Cvoid},), evp_key)
    end
    return pem
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
        push!(lines, b64[i:min(i + 63, end)])
    end
    push!(lines, "-----END $label-----\n")
    join(lines, "\n")
end

"""
    extract_pubkey_pem_from_der(der::Vector{UInt8})::String

Wrap raw DER bytes as PEM, labeling as PUBLIC KEY. 

Does not validate or parse certificate structure.

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
function extract_pubkey_pem_from_der(der::Vector{UInt8})::String
    b64 = base64encode(der)
    lines = ["-----BEGIN PUBLIC KEY-----"]
    for i = 1:64:length(b64)
        push!(lines, b64[i:min(i + 63, end)])
    end
    push!(lines, "-----END PUBLIC KEY-----\n")
    return join(lines, "\n")
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
    # TODO: Use OpenSSL for DER/PEM and validate key field lengths.
    b64 = match(r"-----BEGIN [A-Z ]+-----(.*?)-----END [A-Z ]+-----"ms, pem)
    b64 === nothing && error("PEM parse error")
    raw = replace(b64.captures[1], r"\s+" => "")
    if length(raw) > 4 * 1024 * 1024   # 4MB size cap
        throw(ArgumentError("PEM body too large"))
    end
    base64decode(raw)
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
See also: [`pem_to_der`](@ref),
[`parse_rsa_pem_ne`](@ref) and [`parse_ed25519_pem_x`](@ref).
"""
function parse_ec_pem_xy(pem::AbstractString)
    der = pem_to_der(pem)
    GC.@preserve der begin
        # 1. Load DER to OpenSSL EVP_PKEY*
        p = Ref{Ptr{UInt8}}(pointer(der))
        len = Clong(length(der))
        pkey = ccall((:d2i_PUBKEY, OpenSSL_jll.libcrypto),
            Ptr{Cvoid}, (Ref{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            Ref{Ptr{Cvoid}}(C_NULL), p, len)
        pkey == C_NULL && error("OpenSSL could not parse PEM as PUBKEY")
        try
            # 2. Downcast to EC_KEY*
            eckey = ccall((:EVP_PKEY_get0_EC_KEY, OpenSSL_jll.libcrypto),
                Ptr{Cvoid}, (Ptr{Cvoid},), pkey)
            eckey == C_NULL && error("Not an EC key")
            group = ccall((:EC_KEY_get0_group, OpenSSL_jll.libcrypto),
                Ptr{Cvoid}, (Ptr{Cvoid},), eckey)
            point = ccall((:EC_KEY_get0_public_key, OpenSSL_jll.libcrypto),
                Ptr{Cvoid}, (Ptr{Cvoid},), eckey)
            # 3. Prepare BIGNUM pointers for x, y
            bn_x = ccall((:BN_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, (),)
            bn_y = ccall((:BN_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, (),)
            try
                ok = ccall((:EC_POINT_get_affine_coordinates_GFp,
                        OpenSSL_jll.libcrypto),
                    Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid},
                        Ptr{Cvoid}),
                    group, point, bn_x, bn_y, C_NULL)
                ok != 1 && error("Failed to get affine coordinates")
                # P-256 is 32 bytes for x and y. Use BN_bn2binpad for 
                # fixed left padded
                x = Vector{UInt8}(undef, 32)
                y = Vector{UInt8}(undef, 32)
                ccall((:BN_bn2binpad, OpenSSL_jll.libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Cint), bn_x, pointer(x), 32)
                ccall((:BN_bn2binpad, OpenSSL_jll.libcrypto), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Cint), bn_y, pointer(y), 32)
                return x, y
            finally
                ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid,
                    (Ptr{Cvoid},), bn_x)
                ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid,
                    (Ptr{Cvoid},), bn_y)
            end
        finally
            ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid,
                (Ptr{Cvoid},), pkey)
        end
    end
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
See also: [`pem_to_der`](@ref) and [`parse_ec_pem_xy`](@ref).
"""
function parse_rsa_pem_ne(pem::AbstractString)
    der = pem_to_der(pem)
    GC.@preserve der begin
        p = Ref{Ptr{UInt8}}(pointer(der))
        len = Clong(length(der))
        pkey = ccall((:d2i_PUBKEY, OpenSSL_jll.libcrypto),
            Ptr{Cvoid}, (Ref{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            Ref{Ptr{Cvoid}}(C_NULL), p, len)
        pkey == C_NULL && error("OpenSSL failed to parse RSA PEM")
        try
            rsa = ccall((:EVP_PKEY_get0_RSA, OpenSSL_jll.libcrypto),
                Ptr{Cvoid}, (Ptr{Cvoid},), pkey)
            rsa == C_NULL && error("Not an RSA key?")
            n = ccall((:RSA_get0_n, OpenSSL_jll.libcrypto), Ptr{Cvoid},
                (Ptr{Cvoid},), rsa)
            e = ccall((:RSA_get0_e, OpenSSL_jll.libcrypto), Ptr{Cvoid},
                (Ptr{Cvoid},), rsa)
            n_bits = ccall((:BN_num_bits, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid},), n)
            e_bits = ccall((:BN_num_bits, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid},), e)
            nlen = (n_bits + 7) ÷ 8
            elen = (e_bits + 7) ÷ 8
            nbytes = Vector{UInt8}(undef, nlen)
            ebytes = Vector{UInt8}(undef, elen)
            ccall((:BN_bn2binpad, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Cint), n, pointer(nbytes), nlen)
            ccall((:BN_bn2binpad, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Cint), e, pointer(ebytes), elen)
            return nbytes, ebytes
        finally
            ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid,
                (Ptr{Cvoid},), pkey)
        end
    end
end

"""
    parse_ed25519_pem_x(pem::AbstractString)::x::Vector{UInt8}

Extract the x-coordinate (32 bytes) from an Ed25519 public key (PEM/SPKI).

Parses a PEM-encoded Ed25519 SubjectPublicKeyInfo as generated by OpenSSL or 
Python and returns the 32-byte raw public key (`x`). This is useful for
verifying Ed25519 signatures.

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
See also: [`pem_to_der`](@ref) and [`parse_ec_pem_xy`](@ref).
"""
function parse_ed25519_pem_x(pem::AbstractString)
    der = pem_to_der(pem)
    GC.@preserve der begin
        p = Ref{Ptr{UInt8}}(pointer(der))
        len = Clong(length(der))
        pkey = ccall((:d2i_PUBKEY, OpenSSL_jll.libcrypto),
            Ptr{Cvoid}, (Ref{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            Ref{Ptr{Cvoid}}(C_NULL), p, len)
        pkey == C_NULL && error("OpenSSL failed to parse Ed25519 PEM")
        try
            xbuf = Vector{UInt8}(undef, 32)
            buflen = Ref{Csize_t}(32)
            ok = ccall((:EVP_PKEY_get_raw_public_key, OpenSSL_jll.libcrypto),
                Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), pkey,
                pointer(xbuf), buflen)
            ok == 1 || error("Failed to get Ed25519 public key bytes")
            return xbuf
        finally
            ccall((:EVP_PKEY_free, OpenSSL_jll.libcrypto), Cvoid,
                (Ptr{Cvoid},), pkey)
        end
    end
end
