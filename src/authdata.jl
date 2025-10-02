export extract_credential_public_key, parse_credential_public_key

"""
    extract_credential_public_key(authData::Vector{UInt8})::Vector{UInt8}

Extract the credential public key bytes from authenticator data.

Returns the raw CBOR-encoded public key (COSE_Key) after parsing 
authData as specified by the WebAuthn/FIDO2 standard.

# Examples

```jldoctest
julia> using WebAuthn

julia> fake_pk = UInt8[0xa5, 0x01, 0x02, 0x03, 0x38, 0x20, 0x01, 0x33, 0x58, 
       0x20];

julia> authData = vcat(zeros(UInt8, 37+16), 
       0x00, 0x10, rand(UInt8, 16), fake_pk);

julia> pkbytes = extract_credential_public_key(authData);
```

See also: [`parse_credential_public_key`](@ref)
"""
function extract_credential_public_key(authData::Vector{UInt8})
    offset = 37
    total_len = length(authData)
    # check required fields exist before slicing
    if total_len < offset + 16 + 2
        throw(ArgumentError("authData too short to contain AAGUID and 
        credId length"))
    end
    offset += 16
    id_len = (authData[offset+1] << 8) | authData[offset+2]
    offset += 2
    if offset + id_len > total_len
        throw(ArgumentError("authData truncated: credId length exceeds buffer"))
    end
    offset += id_len
    if offset > total_len
        throw(ArgumentError("authData truncated before public key bytes"))
    end
    pk_bytes = authData[offset+1:end]
    return pk_bytes
end


const AUTHDATA_OFFSET = 37
const AAGUID_LEN = 16

"""
    parse_credential_public_key(authData::Vector{UInt8})::WebAuthnPublicKey

Extract and parse credential public key from authenticator data.

Reads the CBOR-encoded credentialPublicKey field from `authData` and returns the
corresponding parsed struct (e.g., `EC2PublicKey`, `RSAPublicKey`, or `OKPPublicKey`).

# Examples

```jldoctest
julia> using WebAuthn, CBOR

julia> x = UInt8[0x2b, 0x80, 0x96, 0x04, 0x72, 0x26, 0x46, 0x00, 0x15, 0x3d, 
                 0x7a, 0xe6, 0x50, 0x3e, 0xd5, 0x84, 0xd1, 0x56, 0xd6, 0xc5, 
                 0x2c, 0x18, 0x8d, 0x7b, 0xb6, 0xf6, 0x8d, 0xe8, 0xa1, 0x24, 
                 0x06, 0xe9];

julia> y = UInt8[0x1d, 0x3a, 0x3f, 0x1c, 0x5e, 0x76, 0x52, 0x9e, 0x11, 0x6e, 
                 0x3e, 0xb7, 0xfc, 0x6a, 0x33, 0xfc, 0x2a, 0xb4, 0x68, 0x62, 
                 0x26, 0x6a, 0x1d, 0x51, 0x72, 0xf3, 0x3c, 0xab, 0x3c, 0x9c, 
                 0xc5, 0x9f];

julia> fake_pk = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y));

julia> authData = vcat(zeros(UInt8, 37+16), 0x00, 0x20, rand(UInt8, 32), fake_pk);


julia> key = parse_credential_public_key(authData);

julia> key isa WebAuthn.EC2PublicKey
true
```

See also: [`extract_credential_public_key`](@ref) and [`cose_key_parse`](@ref).
"""
function parse_credential_public_key(authData::Vector{UInt8})
    offset = AUTHDATA_OFFSET
    total_len = length(authData)

    if total_len < offset + AAGUID_LEN + 2
        throw(ArgumentError("authData too short to parse credential 
        public key"))
    end

    offset += AAGUID_LEN
    credlen = (authData[offset+1] << 8) | authData[offset+2]
    offset += 2

    if offset + credlen > total_len
        throw(ArgumentError("authData truncated: credId length exceeds buffer"))
    end

    offset += credlen
    if offset > total_len
        throw(ArgumentError("authData truncated before credentialPublicKey"))
    end

    pk_bytes = authData[offset+1:end]
    cose = CBOR.decode(pk_bytes)

    return cose_key_parse(cose)
end