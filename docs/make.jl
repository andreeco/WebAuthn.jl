using WebAuthn
using Documenter

DocMeta.setdocmeta!(WebAuthn, :DocTestSetup, :(using WebAuthn); recursive=true)

makedocs(;
    modules=[WebAuthn],
    authors="André Herling <andreeco@herling.pro>",
    sitename="WebAuthn.jl",
    format=Documenter.HTML(;
        canonical="https://andreeco.github.io/WebAuthn.jl",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/andreeco/WebAuthn.jl",
    devbranch="main",
)
