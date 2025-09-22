# test_option_builders.jl
# -------------------------------
# Purpose: Ensure registration_options and authentication_options produce fully
# spec-compliant WebAuthn option dicts for navigator.credentials .create/.get
# Spec: §5.4, §5.5 (mandatory+optional fields, correct types)
# Tests:
#   - Field presence/type for all required/optional params
#   - ExcludeCredentials, allowCredentials constructed correctly
#   - Challenge direct injection/tested
using Test, WebAuthn

@testset "registration_options content" begin
    opts = registration_options("example.com", "Acme", UInt8[0x22, 0x33],
        "bobby", "Bob Display";
        exclude_ids=["FOO", "BAR"],
        challenge="abc123")
    @test haskey(opts, "user")
    user = opts["user"]
    @test user["id"] == base64urlencode(UInt8[0x22, 0x33])
    @test user["name"] == "bobby"
    @test user["displayName"] == "Bob Display"

    rp = opts["rp"]
    @test rp["id"] == "example.com"
    @test rp["name"] == "Acme"

    @test opts["challenge"] == "abc123"  # direct inject OK
    @test isa(opts["pubKeyCredParams"], Vector)
    @test any(p -> p["alg"] == -7, opts["pubKeyCredParams"])
    @test any(p -> p["alg"] == -257, opts["pubKeyCredParams"])
    @test opts["attestation"] == "none"
    @test opts["timeout"] == 60000

    @test haskey(opts, "excludeCredentials")
    @test length(opts["excludeCredentials"]) == 2
    @test opts["excludeCredentials"][1]["type"] == "public-key"
    @test opts["excludeCredentials"][1]["id"] == "FOO"

    @test haskey(opts, "authenticatorSelection")
    asel = opts["authenticatorSelection"]
    @test asel["residentKey"] == "preferred"
    @test asel["userVerification"] == "preferred"
end

@testset "authentication_options content" begin
    # Unspecified challenge: random string, b64url, correct length
    opts = authentication_options("example.com";
        allow_credential_ids=["abc", "def"])
    @test opts["rpId"] == "example.com"
    @test isa(opts["challenge"], String)
    @test length(base64urldecode(opts["challenge"])) >= 16
    @test isa(opts["allowCredentials"], Vector)
    @test all(x -> x["type"] == "public-key", opts["allowCredentials"])
    @test opts["allowCredentials"][1]["id"] == "abc"
    @test opts["allowCredentials"][2]["id"] == "def"
    @test opts["userVerification"] == "preferred"
    @test opts["timeout"] == 60000
end

@testset "registration_options: default challenge uniqueness/entropy" begin
    chal1 = registration_options("ex", "n", 1, "a", "b")["challenge"]
    chal2 = registration_options("ex", "n", 2, "a", "b")["challenge"]
    @test chal1 != chal2
    @test length(base64urldecode(chal1)) >= 16
end

@testset "authentication_options: challenge injection" begin
    opts = authentication_options("site.com"; challenge="foobar",
        allow_credential_ids=[])
    @test opts["challenge"] == "foobar"
end

@testset "registration_options: minimal user id formats" begin
    # id as string
    opts1 = registration_options("foo.com", "Bar", "abcxyz", "n", "n")
    @test typeof(opts1["user"]["id"]) == String
    # id as UInt8 vector
    opts2 = registration_options("foo.com", "Bar", UInt8[1, 2, 3, 4], "n", "n")
    @test typeof(opts2["user"]["id"]) == String
    @test base64urldecode(opts2["user"]["id"]) == UInt8[1, 2, 3, 4]
end

@testset "registration_options: negative/wrong" begin
    # Invalid: missing user_name field (should error or fill default, 
    # depending on your code)
    try
        registration_options("foo.com", "Bar", 123, "", "Display")
        @test false  # Should fail if 'user_name' is required non-empty
    catch
        @test true
    end
    # Invalid: long user id (>64 bytes)
    uid = rand(UInt8, 65)
    try
        registration_options("foo.com", "Bar", uid, "a", "b")
        @test false
    catch
        @test true
    end
end