using Test, WebAuthn

@testset "registration_options content (required and optional fields)" begin
    opts = registration_options("example.com", "Acme", UInt8[0x22, 0x33],
        "bobby", "Bob Display"; exclude_ids=["FOO", "BAR"], challenge="abc123")
    @test haskey(opts, "user")
    user = opts["user"]
    @test user["id"] == base64urlencode(UInt8[0x22, 0x33])
    @test user["name"] == "bobby"
    @test user["displayName"] == "Bob Display"
    rp = opts["rp"]
    @test rp["id"] == "example.com"
    @test rp["name"] == "Acme"
    @test opts["challenge"] == "abc123"
    # Key params check for compliance
    @test isa(opts["pubKeyCredParams"], Vector)
    @test any(p -> p["alg"] == -7, opts["pubKeyCredParams"])
    @test any(p -> p["alg"] == -257, opts["pubKeyCredParams"])
    # Attestation, timeout (defaults and explicit)
    @test opts["attestation"] == "none"
    @test opts["timeout"] == 60000
    # ExcludeCredentials correctness
    @test haskey(opts, "excludeCredentials")
    @test length(opts["excludeCredentials"]) == 2
    @test opts["excludeCredentials"][1]["type"] == "public-key"
    @test opts["excludeCredentials"][1]["id"] == "FOO"
    @test haskey(opts, "authenticatorSelection")
    asel = opts["authenticatorSelection"]
    @test asel["residentKey"] == "preferred"
    @test asel["userVerification"] == "preferred"
end

@testset "authentication_options content (structure, types, allowCredentials)" begin
    opts = authentication_options("example.com"; allow_credential_ids=["abc", 
    "def"])
    @test opts["rpId"] == "example.com"
    @test isa(opts["challenge"], String)
    @test length(base64urldecode(opts["challenge"])) >= 16
    @test isa(opts["allowCredentials"], Vector)
    @test all(x -> x["type"] == "public-key", opts["allowCredentials"])
    @test opts["allowCredentials"][1]["id"] == "abc"
    @test opts["allowCredentials"][2]["id"] == "def"
    # Default: userVerification preferred, timeout 60000
    @test opts["userVerification"] == "preferred"
    @test opts["timeout"] == 60000
end

@testset "JSON parse/encode roundtrip for authentication_options" begin
    opts = authentication_options("example.com";
        allow_credential_ids=["abc"])
    opts_json = JSON3.write(opts)
    opts_back = JSON3.read(opts_json, Dict)
    @test opts_back["rpId"] == "example.com"
end

@testset "authentication_options extension handling (extensions, appid)" begin
    opts = authentication_options("example.com"; extensions=Dict(
        "appid" => true))
    @test haskey(opts, "extensions")
    @test opts["extensions"]["appid"]
end

@testset "registration_options content (pubKeyCredParams required algs)" begin
    opts = registration_options("x", "y", "id", "n", "n")
    @test any(p->p["alg"] == -7, opts["pubKeyCredParams"])
end

@testset "registration_options: negative (length/required fields)" begin
    @test_throws ArgumentError registration_options("foo.com", "Bar", "", 
    "nn", "disp")
end

@testset "registration_options: default challenge uniqueness/entropy" begin
    chal1 = registration_options("ex", "n", 1, "a", "b")["challenge"]
    chal2 = registration_options("ex", "n", 2, "a", "b")["challenge"]
    @test chal1 != chal2
    @test length(base64urldecode(chal1)) >= 16
end

@testset "authentication_options challenge injection" begin
    opts = authentication_options("site.com"; challenge="foobar", 
    allow_credential_ids=[])
    @test opts["challenge"] == "foobar"
end

@testset "registration_options: minimal user id formats" begin
    # ID as string
    opts1 = registration_options("foo.com", "Bar", "abcxyz", "n", "n")
    @test typeof(opts1["user"]["id"]) == String
    # ID as UInt8 vector
    opts2 = registration_options("foo.com", "Bar", UInt8[1, 2, 3, 4], "n", "n")
    @test typeof(opts2["user"]["id"]) == String
    @test base64urldecode(opts2["user"]["id"]) == UInt8[1, 2, 3, 4]
end

@testset "registration_options: negative (lenght/required fields)" begin
    # Missing user_name (should error)
    try
        registration_options("foo.com", "Bar", 123, "", "Display")
        @test false
    catch
        @test true
    end
    # User id too long (>64 bytes)
    uid = rand(UInt8, 65)
    try
        registration_options("foo.com", "Bar", uid, "a", "b")
        @test false
    catch
        @test true
    end
end

@testset "registration_options: ExcludeCredentials empty allowed" begin
    opts = registration_options("demo.com", "Demo", 42, "bob", "Bob")
    @test isa(opts["excludeCredentials"], Vector)
    @test isempty(opts["excludeCredentials"])
end

@testset "authentication_options: allowCredentials empty legal" begin
    opts = authentication_options("demo2.com")
    @test isa(opts["allowCredentials"], Vector)
    @test isempty(opts["allowCredentials"])
end

@testset "store() on PublicKeyCredential throws error" begin
    err = nothing
    try
        # emulates the browser's store() (not supported in server)
        store()
    catch e
        err = e
    end
    @test err !== nothing
end

@testset "verify_origin checks expected url" begin
    cdj = Dict("origin" => "https://webauthn.example")
    @test verify_origin(cdj, "https://webauthn.example")
    @test_throws ArgumentError verify_origin(cdj, "https://evil.example")
end