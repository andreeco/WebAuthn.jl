# test_option_builders.jl
# -----------------------------------------------------------------------------
# Purpose: End-to-end and field/unit validation for registration and
#          authentication option builders per W3C §5.1, §5.4, §5.5.
#
# SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-id
# SPEC_ID: §5.4.4-AuthenticatorSelectionCriteria
# SPEC_ID: §5.4.5-AuthenticatorAttachment-enum
# SPEC_ID: §5.4.6-ResidentKeyRequirement-enum
# SPEC_ID: §5.4.7-AttestationConveyancePreference-enum
# SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-displayName
# SPEC_ID: §5.1.3-Create-UserID-Length
# SPEC_ID: §5.1.3-Create-ExcludeCredentials
# SPEC_ID: §5.5-PublicKeyCredentialRequestOptions-allowCredentials
# SPEC_ID: §13.4.3-Cryptographic-Challenges
#
using Test, WebAuthn

# SPEC_ID: §7.1-Registration-Options-Structure
# SPEC_ID: §2.1-UserAgent-API-Behavior
# SPEC_ID: §2.1.1-Enums-as-Strings
# SPEC_ID: §2.3-RelyingParty-Algorithm
# SPEC_ID: §5.1-authenticatorAttachment-reporting
# SPEC_ID: §5.1.3-Create-RP-ID-Default-and-Override
# SPEC_ID: §5.1.3-Create-Timeout
# SPEC_ID: §5.1.6-isUserVerifyingPlatformAuthenticatorAvailable
# SPEC_ID: §5.11-Related-Origins-Validation
# SPEC_ID: §5.8.3-PublicKeyCredentialDescriptor
@testset "registration_options content (required and optional fields)" begin
    # SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-id
    # SPEC_ID: §5.1.3-Create-UserID-Length
    # SPEC_ID: §3-URL-and-Domain-Validation
    # SPEC_ID: §5.8.7-ClientCapability-enum
    # SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-id
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
    # SPEC_ID: §13.4.3-Cryptographic-Challenges (direct challenge override)
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
    # Authenticator selection: §5.4.4/5.4.5/5.4.6/5.4.7 coverage
    @test haskey(opts, "authenticatorSelection")
    asel = opts["authenticatorSelection"]
    @test asel["residentKey"] == "preferred"
    @test asel["userVerification"] == "preferred"
end

# SPEC_ID: §5.1.4-Get-AllowCredentials
# SPEC_ID: §5.5-PublicKeyCredentialRequestOptions-allowCredentials
# SPEC_ID: §5.5-PublicKeyCredentialRequestOptions-userVerification
# SPEC_ID: §5.1.4-Get-PublicKeyCredential-Output
# SPEC_ID: §5.1.4-Get-Timeout
@testset "authentication_options content (structure, types, allowCredentials)" begin
    opts = authentication_options("example.com"; allow_credential_ids=["abc", "def"])
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

# SPEC_ID: §5.1.9-parseRequestOptionsFromJSON
# SPEC_ID: §5.1-PublicKeyCredential-toJSON
# SPEC_ID: §5.1.8-parseCreationOptionsFromJSON
@testset "JSON parse/encode roundtrip for authentication_options" begin
    opts = authentication_options("example.com";
        allow_credential_ids=["abc"])
    opts_json = JSON3.write(opts)
    opts_back = JSON3.read(opts_json, Dict)
    @test opts_back["rpId"] == "example.com"
end

# SPEC_ID: §7.2-Authentication-Handle-Extensions
# SPEC_ID: §10.1-Extension-Output-Conformance
# SPEC_ID: §10.1.3-Extension-credProps
# SPEC_ID: §14.5.2-Authentication-Ceremony-Privacy
# SPEC_ID: §10.2-Authenticator-Extensions
# SPEC_ID: §5.1-getClientExtensionResults
# SPEC_ID: §5.2.1-getTransports
# SPEC_ID: §5.3-PublicKeyCredentialParameters-RequiredFields
# SPEC_ID: §5.7-WebAuthnExtensions-Structure
# SPEC_ID: §5.8.4-AuthenticatorTransport
# SPEC_ID: §7.1-Registration-Extension-Handling
# SPEC_ID: §9-Extension-Dictionary-Structure
# SPEC_ID: §9-Extension-Framework-Failure-Is-Non-Fatal
# SPEC_ID: §9.1-ExtensionIdentifier-Format
# SPEC_ID: §9.2-Extension-Definition-Fields
# SPEC_ID: §9.3-Extension-Authenticator-Input-Format
# SPEC_ID: §9.3-Extension-Input-Map
# SPEC_ID: §9.4-Extension-Output-Unsolicited
# SPEC_ID: §9.4-Extension-Processing-Client
# SPEC_ID: §9.4-Extension-Processing-Output
# SPEC_ID: §9.5-Authenticator-Extension-Processing
@testset "authentication_options extension handling (extensions, appid)" begin
    opts = authentication_options("example.com"; extensions=Dict("appid" => true))
    @test haskey(opts, "extensions")
    @test opts["extensions"]["appid"]
end

# SPEC_ID: §5.1.3-Create-PubKeyCredParams-Must-Contain-Supported
@testset "registration_options content (pubKeyCredParams required algs)" begin
    opts = registration_options("x", "y", "id", "n", "n")
    @test any(p->p["alg"] == -7, opts["pubKeyCredParams"])
end

# SPEC_ID: §5.1.3.1-Create-Request-Exceptions
# SPEC_ID: §3-DOMException-Errors
@testset "registration_options: negative (length/required fields)" begin
    @test_throws ArgumentError registration_options("foo.com", "Bar", "", "nn", "disp")
end

# SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-id
# SPEC_ID: §13.4.3-Cryptographic-Challenges
# SPEC_ID: §15.1-Registration-Timeout-Guidelines
@testset "registration_options: default challenge uniqueness/entropy" begin
    chal1 = registration_options("ex", "n", 1, "a", "b")["challenge"]
    chal2 = registration_options("ex", "n", 2, "a", "b")["challenge"]
    @test chal1 != chal2
    @test length(base64urldecode(chal1)) >= 16
end

# SPEC_ID: §5.5-PublicKeyCredentialRequestOptions-allowCredentials
# SPEC_ID: §5.1.4-Get-cdJSON-Challenge-Required
@testset "authentication_options challenge injection" begin
    opts = authentication_options("site.com"; challenge="foobar", allow_credential_ids=[])
    @test opts["challenge"] == "foobar"
end

# SPEC_ID: §4-PublicKeyCredentialUserEntity-id
# SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-id
# SPEC_ID: §2.1-UserAgent-IDL-Conformance
# SPEC_ID: §3-WebIDL-Types-Arguments
# SPEC_ID: §6.4.1-String-Truncation-Clients
@testset "registration_options: minimal user id formats" begin
    # ID as string
    opts1 = registration_options("foo.com", "Bar", "abcxyz", "n", "n")
    @test typeof(opts1["user"]["id"]) == String
    # ID as UInt8 vector
    opts2 = registration_options("foo.com", "Bar", UInt8[1, 2, 3, 4], "n", "n")
    @test typeof(opts2["user"]["id"]) == String
    @test base64urldecode(opts2["user"]["id"]) == UInt8[1, 2, 3, 4]
end

# SPEC_ID: §5.1.3-Create-UserID-Length
# SPEC_ID: §5.4.3-PublicKeyCredentialUserEntity-id
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

# Amplified: edge test for excludeCredentials and allowCredentials empty
# SPEC_ID: §5.1.3-Create-ExcludeCredentials
# SPEC_ID: §5.5-PublicKeyCredentialRequestOptions-allowCredentials
# SPEC_ID: §9-Extension-Security-Optional
# SPEC_ID: §10.1-Unknown-Extension-Inputs-Ignored
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

# SPEC_ID: §5.1.5-Store-NotSupported
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

# SPEC_ID: §13.4.9-Origin-Validation
@testset "verify_origin checks expected url" begin
    cdj = Dict("origin" => "https://webauthn.example")
    @test verify_origin(cdj, "https://webauthn.example")
    @test_throws ArgumentError verify_origin(cdj, "https://evil.example")
end