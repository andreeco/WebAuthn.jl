# https://www.w3.org/TR/webauthn-3/ is the basis!

using TOML, WebAuthn

const TOML_FILE = joinpath(
    dirname(pathof(WebAuthn)), "..", "test", "spec", "webauthn_v3_coverage.toml")

const TEST_DIR = joinpath(dirname(pathof(WebAuthn)), "..", "test")

function load_spec_ids(path::AbstractString;
    coverage::Union{Nothing,String}=nothing)
    spec_toml = TOML.parsefile(path)
    if coverage === nothing
        [entry["id"] for entry in spec_toml["spec"]]
    else
        [entry["id"] for entry in spec_toml["spec"] if
         get(entry, "coverage", nothing) == coverage]
    end
end

function find_referenced_spec_ids_in_tests(testdir::AbstractString)
    ids = String[]
    for (root, dirs, files) in walkdir(testdir)
        for fname in files
            endswith(fname, ".jl") || continue
            fpath = joinpath(root, fname)
            for line in eachline(fpath)
                # Match @testset "§..." or any line containing §X.Y
                for m in eachmatch(
                    r"""\s*SPEC_ID:\s*(§\d+(\.\d+)*[A-Za-z0-9\-]*)""", line)
                    push!(ids, m.captures[1])
                end
            end
        end
    end
    unique(ids)
end

function print_specs_id(spec_ids)
    for i in spec_ids
        println("SPEC_ID: " * i)
    end
end

@info "The following SPEC_IDs use coverage=\"Automated\" in the TOML spec but 
do not appear in any test file as SPEC_ID annotation."

@info "In many cases, the requirement may in fact be tested, but a 
SPEC_ID annotation is missing. Review and annotate as progress continues."
spec_ids = Set(load_spec_ids(TOML_FILE, coverage="Automated"))
#spec_ids = Set(load_spec_ids(TOML_FILE))
test_ids = Set(find_referenced_spec_ids_in_tests(TEST_DIR))

missing_ids = setdiff(spec_ids, test_ids)
orphaned_ids = setdiff(test_ids, spec_ids)

for i in missing_ids
    @info "$i is missing"
end

for i in orphaned_ids
    @info "$i is orphaned"
end