using Test, WebAuthn, CBOR, Dates, JSON3, SHA, Sodium, Logging, Base64

@warn "AI involvement in test coverage may deceive about how 
thoroughly the code is tested. Human review wanted and needed!
Also the annotations of SPEC_ID must be checked!
"

#include("helpers/asn1.jl")

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

function include_all_jl(dir)
    for f in readdir(dir; join=true)
        if isdir(f)
            include_all_jl(f)
        elseif endswith(f, ".jl") && basename(f) != "runtests.jl"
            include(f)
        end
    end
end
include_all_jl(@__DIR__)

@testset "WebAuthn.jl" begin
    # Write your tests here.
end


#=
using Test, WebAuthn, CBOR, Dates, JSON3, SHA, Sodium, Logging, Base64


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

=#
