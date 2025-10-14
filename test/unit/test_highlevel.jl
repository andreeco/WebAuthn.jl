using Test, WebAuthn, Random, CBOR, JSON3, Sodium, SHA

@testset "WebAuthn Unified High-Level API" begin
    # --- SIMULATE A REGISTRATION ---

    # 1. Generate Ed25519 keypair
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0

    # 2. Build credential id and challenge
    cred_id_bytes = rand(UInt8, 16)
    cred_id_b64 = WebAuthn.base64urlencode(cred_id_bytes)
    challenge = WebAuthn.generate_challenge(32)
    origin = "https://example.com"

    # 3. CBOR COSE_Key for Ed25519
    cose_pk = Dict(1 => 1, 3 => -8, -1 => 6, -2 => pk)
    pk_cbor = CBOR.encode(cose_pk)

    # 4. Compose authenticatorData (simplified example)
    rpIdHash = SHA.sha256(Vector{UInt8}("example.com"))
    flags = 0x41 | 0x04 
    signCount = [0x00, 0x00, 0x00, 0x01]
    aaguid = zeros(UInt8, 16)
    credlen = [0x00, 0x10]  # 16 bytes
    authData = vcat(rpIdHash, flags, signCount, aaguid, credlen, 
    cred_id_bytes, pk_cbor)

    # 5. Build attestation object ("none" attestation)
    attobj_dict = Dict("fmt" => "none", "authData" => authData, 
    "attStmt" => Dict())
    attobj_cbor = CBOR.encode(attobj_dict)
    attobj_b64 = WebAuthn.base64urlencode(attobj_cbor)

    # 6. clientDataJSON
    clientData_dict = Dict(
        "type" => "webauthn.create",
        "challenge" => challenge,
        "origin" => origin
    )
    clientDataJSON = JSON3.write(clientData_dict)
    clientDataJSON_b64 = WebAuthn.base64urlencode(Vector{UInt8}(clientDataJSON))

    # 7. Simulated registration response (as browser sends)
    reg_response = Dict(
        "response" => Dict(
            "attestationObject" => attobj_b64,
            "clientDataJSON" => clientDataJSON_b64,
        ),
        "id" => cred_id_b64
    )

    # --- HAPPY CASE ---
    reg_result = verify_registration_response(reg_response;
        expected_challenge=challenge, expected_origin=origin)
    @test reg_result.ok
    @test reg_result.public_key isa OKPPublicKey
    @test reg_result.credential_id == cred_id_b64

    # --- ERRORS ---
    # Wrong challenge
    bad_reg = deepcopy(reg_response)
    bad_reg["response"]["clientDataJSON"] = WebAuthn.base64urlencode(
        Vector{UInt8}(JSON3.write(Dict(
            "type" => "webauthn.create", "challenge" => "notarealchal",
            "origin" => origin))))
    fail = verify_registration_response(bad_reg; 
    expected_challenge=challenge, expected_origin=origin)
    @test !fail.ok
    @test occursin("challenge", lowercase(fail.reason))

    # Wrong origin
    bad_reg2 = deepcopy(reg_response)
    bad_reg2["response"]["clientDataJSON"] = WebAuthn.base64urlencode(
        Vector{UInt8}(JSON3.write(Dict(
            "type" => "webauthn.create", "challenge" => challenge,
            "origin" => "https://evil.site"))))
    fail2 = verify_registration_response(bad_reg2; 
    expected_challenge=challenge, expected_origin=origin)
    @test !fail2.ok
    @test occursin("origin", lowercase(fail2.reason))

    # --- SIMULATE AUTHENTICATION ---
    clientData_authn_dict = Dict(
        "type" => "webauthn.get",
        "challenge" => challenge,
        "origin" => origin
    )
    clientDataJSON_authn = JSON3.write(clientData_authn_dict)
    clientDataJSON_authn_b64 = WebAuthn.base64urlencode(
        Vector{UInt8}(clientDataJSON_authn))

    # Compose signature
    msg = vcat(authData, SHA.sha256(Vector{UInt8}(clientDataJSON_authn)))
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{Culonglong}()
    @test Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk) == 0

    # Assertion response (canonical)
    assert_response = Dict(
        "response" => Dict(
            "authenticatorData" => WebAuthn.base64urlencode(authData),
            "clientDataJSON" => clientDataJSON_authn_b64,
            "signature" => WebAuthn.base64urlencode(sig),
        ),
        "id" => cred_id_b64
    )

    # --- HAPPY CASE ---
    authn_result = verify_authentication_response(assert_response;
        public_key=reg_result.public_key, expected_challenge=challenge,
        expected_origin=origin, previous_signcount=0)
    @test authn_result.ok
    @test authn_result.credential_id == cred_id_b64

    # --- SIGNATURE ERROR ---
    bad_sig = copy(sig)
    bad_sig[1] ⊻= 0xFF
    bad_assert = deepcopy(assert_response)
    bad_assert["response"]["signature"] = WebAuthn.base64urlencode(bad_sig)
    fail_authn = verify_authentication_response(bad_assert;
        public_key=reg_result.public_key, expected_challenge=challenge,
        expected_origin=origin, previous_signcount=0)
    @test !fail_authn.ok
    @test occursin("signature", lowercase(fail_authn.reason))

    # --- SIGNCOUNT ERROR ---
    fail_signcount = verify_authentication_response(assert_response;
        public_key=reg_result.public_key, expected_challenge=challenge,
        expected_origin=origin, previous_signcount=10)
    @test !fail_signcount.ok
    let r = get(fail_signcount, :reason, nothing)
        @test r !== nothing && occursin("signcount", lowercase(String(r)))
    end

    # --- USER PRESENCE/UV ERROR ---
    bad_ad = copy(authData)
    bad_ad[33] &= ~0x01
    bad_up = deepcopy(assert_response)
    bad_up["response"]["authenticatorData"] = WebAuthn.base64urlencode(bad_ad)
    fail_up = verify_authentication_response(bad_up;
        public_key=reg_result.public_key, expected_challenge=challenge,
        expected_origin=origin, previous_signcount=0)
    @test !fail_up.ok
    let r = get(fail_up, :reason, nothing)
        @test r !== nothing && (occursin("user presence", String(r)) || 
        occursin("signature", lowercase(String(r))))
    end
end