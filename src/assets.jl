export load_vector, VECTORS_DIR

const _ASSET_DIR = joinpath(@__DIR__, "..", "artifacts")

"""
    asset_path(name::AbstractString)::String

Get absolute path to an asset shipped with WebAuthn.jl.
"""
asset_path(name::AbstractString) = joinpath(_ASSET_DIR, name)

"""
    asset(name::AbstractString)::String

Read and return the contents of an asset script (e.g. JS file) shipped 
with WebAuthn.jl. Example: `WebAuthn.asset("webauthn_register.js")`
"""
function asset(name::AbstractString)
    read(asset_path(name), String)
end

const VECTORS_DIR = joinpath(dirname(pathof(WebAuthn)),
    "..", "test", "vectors")

function load_vector(parts::AbstractString...)
    f = joinpath(VECTORS_DIR, parts...)
    @assert isfile(f) "$f not found"
    ext = lowercase(splitext(f)[2])
    if ext in (".der", ".cbor", ".bin")
        return read(f) # Vector{UInt8}
    else
        return read(f, String) # UTF-8 String
    end
end