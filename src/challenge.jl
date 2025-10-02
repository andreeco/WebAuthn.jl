export generate_challenge, verify_challenge

"""
    generate_challenge([n=32])::String

Generate a random base64url-encoded challenge of n bytes.

# Examples
```jldoctests
julia> using WebAuthn

julia> challenge = generate_challenge();

julia> length(base64urldecode(challenge))
32
```
"""
generate_challenge(n::Int=32) = base64urlencode(rand(RandomDevice(), UInt8, n))

function _constant_time_eq(a::Vector{UInt8}, b::Vector{UInt8})
    length(a) == length(b) || return false
    diff = 0
    for i in eachindex(a)
        diff |= xor(a[i], b[i])
    end
    return diff == 0
end

"""
    verify_challenge(clientDataJSON_b64, expected_challenge_b64)::Bool

Verify the clientDataJSON challenge matches the expected challenge.

# Examples

```jldoctest
julia> using WebAuthn, JSON3

julia> challenge = generate_challenge(16);

julia> cdj = JSON3.write(Dict("type"=>"webauthn.create",
            "challenge"=>challenge, "origin"=>"https://site"));

julia> cdj_b64 = base64urlencode(Vector{UInt8}(cdj));

julia> verify_challenge(cdj_b64, challenge)
true
```

See also: [`generate_challenge`](@ref)
"""
function verify_challenge(clientDataJSON_b64::AbstractString,
    expected_challenge_b64::AbstractString)
    actual = parse_clientdata_json(clientDataJSON_b64)["challenge"]
    # Compare both direct string and decoded bytes in constant time
    if actual == expected_challenge_b64
        return true
    end
    a_dec = base64urldecode(actual)
    b_dec = base64urldecode(expected_challenge_b64)
    return _constant_time_eq(a_dec, b_dec)
end