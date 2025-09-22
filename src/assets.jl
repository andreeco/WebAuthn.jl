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
