using Test, WebAuthn, CBOR, Dates, JSON3, SHA, Sodium, Logging, Base64

include("helpers/asn1.jl")

const TESTVEC_DIR = joinpath(dirname(pathof(WebAuthn)),
    "..", "test", "vectors")

function load_der(name)
    read(joinpath(TESTVEC_DIR, "der_testvectors", "$name.der"))
end

# directory should change?
function load_pem(name)
    read(joinpath(TESTVEC_DIR, "der_testvectors", "$name.pem"), String)
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


