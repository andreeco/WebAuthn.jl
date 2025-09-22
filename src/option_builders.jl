export registration_options, authentication_options

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
        throw(ArgumentError("user.id must be between 1 and 64 bytes 
        (got $(length(ubytes)))"))
    end
    if isempty(user_name)
        throw(ArgumentError("user.name required & must not be empty"))
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