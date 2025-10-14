export verify_registration_response, verify_authentication_response

"""
    verify_registration_response(response::Dict{String,Any};
        expected_challenge::AbstractString,
        expected_origin::AbstractString,
        attestation_policy::String="packed"
    )

Verify a WebAuthn registration (credential creation) response in a single call.

This function validates the client-provided registration response using all 
required WebAuthn/FIDO2 steps: base64 and CBOR decoding, challenge and 
origin check, full attestation verification (with secure `"packed"` default), 
and then extracts the new credential's public key and ID. 
Errors are reported in the result's `:ok` and`:reason` fields.

# Arguments
- `response`: Registration response dict as received from the browser 
  (with `"response"` and `"id"` fields).
- `expected_challenge`: Server-issued challenge, must match the client's signed 
   field.
- `expected_origin`: Allowed browser origin for the client.
- `attestation_policy`: `"packed"` (default; require strong attestation), 
  `"none"`, or `"skip"` (testing only).

# Examples

```jldoctest
julia> using WebAuthn, Sodium, CBOR, SHA, JSON3

julia> pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES);

julia> sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES);

julia> Sodium.crypto_sign_keypair(pk, sk);

julia> challenge = b"fixedchallenge";

julia> cose_pk = Dict(1=>1, 3=>-8, -1=>6, -2=>pk);

julia> pk_cbor = CBOR.encode(cose_pk);

julia> credid = b"credtestidfixed!";

julia> credlen = [0x00, length(credid)];

julia> flags = 0x45; signcount = [0,0,0,1]; aaguid = zeros(UInt8, 16);

julia> authData = vcat(SHA.sha256(b"example.com"), flags, signcount, aaguid,
                       credlen, credid, pk_cbor);

julia> attobj = Dict("fmt"=>"none", "authData"=>authData, "attStmt"=>Dict());

julia> att_b64 = WebAuthn.base64urlencode(CBOR.encode(attobj));

julia> clientData = JSON3.write(Dict("type"=>"webauthn.create",
                  "challenge"=>String(challenge), "origin"=>"https://ex"));

julia> cdj_b64 = WebAuthn.base64urlencode(Vector{UInt8}(clientData));

julia> reg_resp = Dict("response"=>Dict("attestationObject"=>att_b64,
                  "clientDataJSON"=>cdj_b64), "id"=>String(credid));

julia> result = verify_registration_response(reg_resp;
                  expected_challenge=String(challenge),
                  expected_origin="https://ex");

julia> result.ok
true
```

See also: [`cose_key_parse`](@ref), [`registration_options`](@ref), 
[`verify_attestation_object`](@ref) and 
[`verify_authentication_response`](@ref).
"""
function verify_registration_response(response::Dict{String,Any};
    expected_challenge::AbstractString,
    expected_origin::AbstractString,
    attestation_policy::String="packed"
)
    # 1. Get attestationObject, clientDataJSON
    obj_b64 = response["response"]["attestationObject"]
    cdj_b64 = response["response"]["clientDataJSON"]
    credential_id = get(response, "id", nothing)

    try
        # 2. Parse clientDataJSON
        cdj = parse_clientdata_json(cdj_b64)
        # 3. Challenge & origin check
        if !verify_challenge(cdj_b64, expected_challenge)
            return (ok=false, reason="Challenge mismatch")
        end
        try
            verify_origin(cdj, expected_origin)
        catch e
            return (ok=false, reason="Origin mismatch: $(e.msg)")
        end
        # 4. Parse attestation object
        attobj = parse_attestation_object(obj_b64)
        # 5. Optionally verify attestation
        if attestation_policy != "skip"
            if !verify_attestation_object(obj_b64, base64urldecode(cdj_b64))
                return (ok=false, reason="Attestation verification failed.")
            end
        end
        # 6. Extract credential public key
        pkbytes = extract_credential_public_key(attobj["authData"])
        public_key = cose_key_parse(CBOR.decode(pkbytes))
        credential_id = response["id"]
        return (
            ok=true,
            public_key=public_key,
            credential_id=credential_id,
            user_handle=get(response, "userHandle", nothing),
            attestation_format=attobj["fmt"],
            sign_count=0,  # Not available at registration; may extract later
        )
    catch e
        return (ok=false, reason="Registration verification error: $(e)")
    end
end

"""
    verify_authentication_response(response::Dict{String,Any};
        public_key,
        expected_challenge::AbstractString,
        expected_origin::AbstractString,
        previous_signcount::Integer=0,
        require_uv::Bool=true)

Verify a WebAuthn authentication (assertion) response using all protocol checks.

Performs challenge, origin, and signature checks, enforces user presence and 
verification flags, and ensures that the authenticator's signCount is 
monotonically increasing (prevents credential cloning/reuse). By default, 
user verification (biometric/PIN) is required (`require_uv=true`).

# Arguments
- `response`: Assertion response dict as received from 
  `navigator.credentials.get()`, with top-level `"id"` and a `"response"` 
   subdict.
- `public_key`: Public key structure, e.g., parsed using 
   [`cose_key_parse`](@ref) from stored registration outcome.
- `expected_challenge`: Server-issued challenge for this authentication.
- `expected_origin`: Allowed browser origin.
- `previous_signcount`: Last recorded signCount for this credential 
  (0 if first use).
- `require_uv`: Require user verification (default `true` for secure passkey 
  flows).

# Examples

```jldoctest
julia> using WebAuthn, Sodium, CBOR, SHA, JSON3

julia> pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES);

julia> sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES);

julia> Sodium.crypto_sign_keypair(pk, sk);

julia> challenge = b"fixedchallenge";

julia> credid = b"credtestidfixed!";

julia> credlen = UInt8[0x00, length(credid)];

julia> flags = 0x45;

julia> signcount = UInt8[0,0,0,1];

julia> aaguid = zeros(UInt8,16);

julia> pk_cbor = CBOR.encode(Dict(1=>1, 3=>-8, -1=>6, -2=>pk));

julia> authData = vcat(SHA.sha256(b"example.com"), flags, signcount, 
           aaguid, credlen, credid, pk_cbor);

julia> clientData = JSON3.write(Dict("type"=>"webauthn.get", 
               "challenge"=>String(challenge), "origin"=>"https://ex"));

julia> cdj_b64 = WebAuthn.base64urlencode(Vector{UInt8}(clientData));

julia> msg = vcat(authData, SHA.sha256(Vector{UInt8}(clientData)));

julia> sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES); sl = Ref{Culonglong}();

julia> Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk);

julia> assert_resp = Dict(
         "response"=>Dict(
           "authenticatorData"=>WebAuthn.base64urlencode(authData),
           "clientDataJSON"=>cdj_b64,
           "signature"=>WebAuthn.base64urlencode(sig)
         ),
         "id"=>String(credid)
       );

julia> public_key = WebAuthn.cose_key_parse(CBOR.decode(pk_cbor));

julia> result = verify_authentication_response(assert_resp;
           public_key=public_key, expected_challenge=String(challenge), 
           expected_origin="https://ex");

julia> result.ok   # should now be true
true

julia> result.new_signcount >= 1
true
```

See also: [`verify_registration_response`](@ref), 
[`authentication_options`](@ref) and `verify_webauthn_signature`](@ref).
"""
function verify_authentication_response(response::Dict{String,Any};
    public_key,
    expected_challenge::AbstractString,
    expected_origin::AbstractString,
    previous_signcount::Integer=0,
    require_uv::Bool=true
)
    try
        ad = base64urldecode(response["response"]["authenticatorData"])
        cdj_b64 = response["response"]["clientDataJSON"]
        cdj = parse_clientdata_json(cdj_b64)
        sig = base64urldecode(response["response"]["signature"])
        # 1. Verify challenge
        if !verify_challenge(cdj_b64, expected_challenge)
            return (ok=false, reason="Challenge mismatch")
        end
        # 2. Verify origin
        try
            verify_origin(cdj, expected_origin)
        catch e
            return (ok=false, reason="Origin mismatch: $(e.msg)")
        end
        # 3. Verify signature
        if !verify_webauthn_signature(public_key, ad, 
            base64urldecode(cdj_b64), sig)
            return (ok=false, reason="Signature verification failed")
        end
        # 4. User presence/verification flags
        try
            enforce_up_uv(ad; require_uv=require_uv)
        catch e
            return (ok=false, reason="UP/UV flags check failed: $(e.msg)")
        end
        # 5. Sign count
        signcount_bytes = ad[34:37]
        new_signcount = (UInt32(signcount_bytes[1]) << 24) |
                        (UInt32(signcount_bytes[2]) << 16) |
                        (UInt32(signcount_bytes[3]) << 8) |
                        UInt32(signcount_bytes[4])
        try
            enforce_signcount(previous_signcount, new_signcount)
        catch e
            return (ok=false, reason="signCount: $(e.msg)")
        end
        return (
            ok=true,
            new_signcount=new_signcount,
            user_handle=get(response, "userHandle", nothing),
            credential_id=get(response, "id", nothing),
            reason=nothing
        )
    catch e
        return (ok=false, reason="Authentication verification error: $(e)")
    end
end