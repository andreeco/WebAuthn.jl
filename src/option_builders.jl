export registration_options, authentication_options
export enforce_signcount, enforce_up_uv, verify_origin

"""
    registration_options(rpid, rpname, user_id, user_name, user_display;
        exclude_ids=[], challenge=nothing,
        attestation="none", timeout=60000, kwargs...)::Dict

Construct WebAuthn registration options for `navigator.credentials.create`.

## Arguments

- `rpid`: relying party identifier (e.g., "example.com").
- `rpname`: display name of the RP.
- `user_id`: user handle (string or byte vector).
- `user_name`: username (string).
- `user_display`: display name (string).

## Keywords

- `exclude_ids`: vector of credential IDs to exclude (default empty).
- `challenge`: challenge string to use (default: random).
- `attestation`: "none" (default), "packed", "direct", "enterprise", etc.
- `timeout`: timeout in ms (default 60000).
- `kwargs`: any additional WebAuthn/PublicKeyCredentialCreationOptions fields;
   future extensions can be set directly as keywords.

## Examples

```jldoctest
julia> using WebAuthn

julia> opts = registration_options("foo.com", "Demo", 123, "bob", 
           "Bob", attestation="packed", extensions=Dict("my_custom"=>"hi"));

julia> opts["attestation"]
"packed"

julia> opts["extensions"]["my_custom"]
"hi"
```
See also: [`authentication_options`](@ref).
"""
function registration_options(rpid::String, rpname::String, user_id,
    user_name::String, user_display::String;
    exclude_ids=Vector{String}(),
    challenge=nothing,
    attestation="none",
    timeout=60000,
    kwargs...
)::Dict{String,Any}
    # Handle user_id encoding and length check
    ubytes = isa(user_id, Vector{UInt8}) ? user_id :
             Vector{UInt8}(string(user_id))
    if length(ubytes) < 1 || length(ubytes) > 64
        throw(ArgumentError("user.id must be between 1 and 64 bytes"))
    end

    if isempty(user_name)
        throw(ArgumentError("user.name is required and must not be empty"))
    end

    # Exclude credentials as needed
    exclude = [Dict("type" => "public-key", "id" => id) for id in exclude_ids]

    # Baseline options
    opts = Dict(
        "rp" => Dict("id" => rpid, "name" => rpname),
        "user" => Dict("id" => base64urlencode(ubytes), "name" => user_name,
            "displayName" => user_display),
        "challenge" => challenge === nothing ? generate_challenge() : challenge,
        "pubKeyCredParams" => [
            Dict("type" => "public-key", "alg" => -7),
            Dict("type" => "public-key", "alg" => -257)
        ],
        "attestation" => attestation,
        "timeout" => timeout,
        "excludeCredentials" => exclude,
        "authenticatorSelection" => Dict(
            "residentKey" => "preferred",
            "userVerification" => "preferred"
        )
    )

    for (k, v) in kwargs
        opts[String(k)] = v
    end

    @debug "WebAuthn registration_options:" opts
    return opts
end

"""
    authentication_options(rpid; allow_credential_ids=[], 
        challenge=nothing, timeout=60000, kwargs...)::Dict

Build a browser authentication options dictionary for 
`navigator.credentials.get`.

# Keywords

- `allow_credential_ids`: List of credential IDs (strings) that are allowed 
   (default: empty).
- `challenge`: Challenge string to use (default: random).
- `timeout`: Timeout in milliseconds (default: 60000).
- `kwargs`: Any additional field for WebAuthn/PublicKeyCredentialRequestOptions; 
   future extensions or browser-specific options can be passed directly as 
   keywords.

# Examples

```jldoctest
julia> using WebAuthn

julia> opts = authentication_options("example.com";
           allow_credential_ids=["id1", "id2"], userVerification="required", 
           extensions=Dict("appid"=>true));

julia> opts["rpId"]
"example.com"

julia> opts["allowCredentials"][1]["id"]
"id1"

julia> opts["userVerification"]
"required"

julia> opts["extensions"]["appid"]
true
```
See also: [`registration_options`](@ref).
"""
function authentication_options(rpid::String;
    allow_credential_ids=Vector{String}(),
    challenge=nothing,
    timeout=60000,
    kwargs...)
    allowcreds = [Dict("type" => "public-key", "id" => id) for id in
                  allow_credential_ids]
    opts = Dict(
        "challenge" => challenge === nothing ? generate_challenge() :
                       challenge,
        "rpId" => rpid,
        "timeout" => timeout,
        "allowCredentials" => allowcreds,
        "userVerification" => "preferred"
    )
    # Insert any extra keyword fields (for spec growth/extensions)
    for (k, v) in kwargs
        opts[String(k)] = v
    end
    @debug "WebAuthn authentication_options:" opts
    return opts
end

"""
    enforce_signcount(old::Integer, new::Integer)

Reject cloned/replayed credentials per WebAuthn spec.

# Examples

```jldoctest
julia> enforce_signcount(0, 20)   # Initial use, old is 0: always OK
true

julia> enforce_signcount(10, 11)  # Normal monotonic increase
true

julia> enforce_signcount(5, 5)    # No increase (should fail)
ERROR: ArgumentError: 
[...]

julia> enforce_signcount(10, 3)   # Replay/clone (should fail)
ERROR: ArgumentError: 
[...]
```
"""
function enforce_signcount(old::Integer, new::Integer)
    (old == 0 && new >= 0) && return true
    (new > old) && return true
    throw(ArgumentError("signCount did not increase — possible cloned 
    authenticator or replay attack"))
end

"""
    enforce_up_uv(authData::Vector{UInt8}; require_uv=false)

Check user presence (UP) and user verification (UV) flags in authenticatorData.

# Examples

```jldoctest
julia> # UP (bit 0) set, UV (bit 2) not set

julia> enforce_up_uv([zeros(UInt8,33); 0x01])
true

julia> # UP and UV set

julia> enforce_up_uv([zeros(UInt8,33); 0x05])
true

julia> # UP not set

julia> enforce_up_uv([zeros(UInt8,33); 0x00])
ERROR: 
[...]

julia> # UP set, require UV (but UV not set)

julia> enforce_up_uv([zeros(UInt8,33); 0x01]; require_uv=true)
ERROR: 
[...]

julia> # UP and UV set, require UV (pass)

julia>  enforce_up_uv([zeros(UInt8,33); 0x05]; require_uv=true)
true
"""
function enforce_up_uv(authData::Vector{UInt8}; require_uv::Bool=false)
    flags = authData[33]
    if (flags & 0x01) == 0
        throw(ArgumentError("User Presence (UP) flag not set in assertion"))
    end
    if require_uv && (flags & 0x04) == 0
        throw(ArgumentError("User Verification (UV) required but not set"))
    end
    return true
end

"""
    verify_origin(cdj::Dict, expected::String)

Check that the 'origin' field in the parsed clientDataJSON matches what you 
expect.

# Examples

```jldoctest
julia> verify_origin(Dict("origin" => "https://demo.test"), "https://demo.test")
true

julia> verify_origin(Dict("origin" => "https://evil.site"), "https://demo.test")
ERROR: ArgumentError: 
[...]

julia> # If 'origin' key is missing in dict

julia> verify_origin(Dict("foo" => 42), "https://demo.test")
ERROR: ArgumentError: 
[...]
```
"""
function verify_origin(cdj::Dict, expected::String)
    if get(cdj, "origin", nothing) != expected
        throw(ArgumentError("Origin mismatch: 
        expected $expected, got $(get(cdj, "origin", nothing))"))
    end
    return true
end
