using Test, WebAuthn, CBOR, Dates, JSON3, SHA, Sodium, Logging

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


