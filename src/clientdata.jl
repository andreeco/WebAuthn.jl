export parse_attestation_object, parse_clientdata_json, parse_assertion

"""
    parse_attestation_object(b64::String)::Dict

Parse a base64url-encoded attestationObject to a dictionary.

Decodes and parses the CBOR-encoded attestation object returned during 
WebAuthn registration.

# Examples

```jldoctest
julia> using WebAuthn, CBOR

julia> attObj_b64 =
           "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikgokmRebwXda2X9CScZAt1" *
           "FS1U7jvFi6aDLY8eyICQjhBAAAAAcDiKS6EGVQBSZ3UWJ8FVioAIJYypOb6RxF" *
           "Q4ocIvwK78qeEYp67CAWrj59jW99h8_tNpQECAyYgASFYIOyFijz315Yd_Aexkt" *
           "5l6YaFK4MK2CQgRZPXQqGGD06MIlgg54dhMxLg9u84Y3urvWdHrViXea0aMYq7v" *
           "7QI-DP1Duk";

julia> obj = parse_attestation_object(attObj_b64);
```

See also: [`parse_clientdata_json`](@ref).
"""
parse_attestation_object(b64::String) = CBOR.decode(base64urldecode(b64))

"""
    parse_clientdata_json(b64::String)::Dict

Parse a base64url-encoded clientDataJSON to a dictionary.

Decodes the clientDataJSON, converting from base64url and UTF-8 JSON to a 
Julia dictionary.

# Examples

```jldoctest
julia> using WebAuthn

julia> json = \"\"\"{\"type\": \"webauthn.get\"}\"\"\";

julia> cdj_b64 = base64urlencode(Vector{UInt8}(json));

julia> cdj = parse_clientdata_json(cdj_b64)
Dict{String, Any} with 1 entry:
  "type" => "webauthn.get"
```

See also: [`parse_attestation_object`](@ref).
"""
parse_clientdata_json(b64::String) = JSON3.read(String(base64urldecode(b64)),
    Dict{String,Any})

"""
    parse_assertion(authdata_b64, sig_b64) -> (authData, signature)

Base64url-decode authenticatorData and signature as a tuple of byte vectors.

Returns the authenticator data and signature, each as a vector of bytes.

# Examples

```jldoctest
julia> using WebAuthn

julia> ad_b64 = base64urlencode(rand(UInt8, 37));

julia> sig_b64 = base64urlencode(rand(UInt8, 64));

julia> ad, sig = parse_assertion(ad_b64, sig_b64);
```

See also: [`parse_attestation_object`](@ref) and
[`parse_clientdata_json`](@ref).
"""
parse_assertion(authdata_b64::AbstractString, sig_b64::AbstractString) = (
    base64urldecode(authdata_b64), base64urldecode(sig_b64))