export base64urlencode, base64urldecode
export generate_challenge

"""
    base64urlencode(bytes::Vector{UInt8})::String

Encode a byte vector to a base64url string without padding.

Replaces `+` with `-` and `/` with `_` for URL safety, then removes padding
characters.

# Examples

```julia
julia> using WebAuthn

julia> base64urlencode(UInt8[1, 2, 3])
"AQID"
```
See also: [`base64urldecode`](@ref).
"""
function base64urlencode(bytes::Vector{UInt8})
    s = base64encode(bytes)
    s = replace(s, '+' => '-', '/' => '_')
    replace(s, '=' => "")
end

"""
    base64urldecode(s::AbstractString)::Vector{UInt8}

Decode a base64url string (URL-safe, no padding) to a byte vector.

Restores standard base64 alphabet and adds padding if necessary before decoding.

# Examples

```jldoctests
julia> using WebAuthn

julia> base64urldecode("AQID")
3-element Vector{UInt8}:
 0x01
 0x02
 0x03
```
See also: [`base64urlencode`](@ref).
"""
function base64urldecode(s::AbstractString)
    s2 = replace(s, '-' => '+', '_' => '/')
    pad = (4 - length(s2) % 4) % 4
    s2 *= "="^pad
    base64decode(s2)
end