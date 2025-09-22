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
    offset += 16
    id_len = (authData[offset+1] << 8) | authData[offset+2]
    offset += 2
    offset += id_len
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

julia> fake_pk = CBOR.encode(Dict(1=>2, 3=>-7, -1=>1, -2=>rand(UInt8,32), 
                 -3=>rand(UInt8,32)));


julia> authData = vcat(zeros(UInt8, 37+16), 0x00, 0x20, rand(UInt8, 32), 
          fake_pk);

julia> key = parse_credential_public_key(authData);

```

See also: [`extract_credential_public_key`](@ref) and [`cose_key_parse`](@ref).
"""
function parse_credential_public_key(authData::Vector{UInt8})
    offset = AUTHDATA_OFFSET
    # required by spec, but not used here
    aaguid = authData[offset+1:offset+AAGUID_LEN]
    offset += AAGUID_LEN
    credlen = (authData[offset+1] << 8) | authData[offset+2]
    offset += 2
    # also not used here
    credid = authData[offset+1:offset+credlen]
    offset += credlen
    pk_bytes = authData[offset+1:end]
    cose_key_parse(CBOR.decode(pk_bytes))
end