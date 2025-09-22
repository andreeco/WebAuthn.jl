export verify_attestation_object, verify_attestation_packed

"""
    verify_attestation_object(attObj_b64, clientDataJSON)::Bool

Verify a WebAuthn attestation object of format "none" or "packed".

# Examples

```jldoctest
julia> using WebAuthn

julia> attObj_b64 =
       "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikgokmRebwXda2X9CScZAt1" *
       "FS1U7jvFi6aDLY8eyICQjhBAAAAAcDiKS6EGVQBSZ3UWJ8FVioAIJYypOb6RxF" *
       "Q4ocIvwK78qeEYp67CAWrj59jW99h8_tNpQECAyYgASFYIOyFijz315Yd_Aexkt" *
       "5l6YaFK4MK2CQgRZPXQqGGD06MIlgg54dhMxLg9u84Y3urvWdHrViXea0aMYq7v" *
       "7QI-DP1Duk";

julia> cdj_b64 =
       "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiazF6eV9hU0N" *
       "PTDdOMFBWVmFVVElpVm5BU1ZGVDE4MDB1TWJVa1R2dUdKSSIsIm9yaWdpbiI6Im" *
       "h0dHBzOi8vd2ViYXV0aG4tdGVzdC5sb2NhbCIsImNyb3NzT3JpZ2luIjpmYWxze" *
       "X0";

julia> clientDataJSON = WebAuthn.base64urldecode(cdj_b64);

julia> ok = verify_attestation_object(attObj_b64, clientDataJSON)
true
```

See also: [`verify_webauthn_signature`](@ref).
"""
function verify_attestation_object(attObj_b64::String,
    clientDataJSON::Vector{UInt8})::Bool
    attobj = parse_attestation_object(attObj_b64)
    fmt = String(attobj["fmt"])
    authData = attobj["authData"]::Vector{UInt8}
    clientDataHash = SHA.sha256(clientDataJSON)
    msg = vcat(authData, clientDataHash)
    if fmt == "none"
        (haskey(attobj, "attStmt") && length(attobj["attStmt"]) != 0) &&
            error("attStmt for format 'none' MUST be empty ({}), 
            got: $(attobj["attStmt"])")
        return true
    elseif fmt == "packed"
        return verify_attestation_packed(attobj["attStmt"], msg, authData,
            clientDataJSON)
    else
        error("Unsupported attestation format: $fmt")
    end
end

#=
julia> using WebAuthn, CBOR, Sodium, SHA

# -- 1. Generate a keypair (Ed25519 for simplicity) --
julia> pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES);
julia> sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES);
julia> Sodium.crypto_sign_keypair(pk, sk);

# -- 2. Create a valid CBOR-encoded COSE key (OKP for Ed25519) --
julia> cose = Dict(1=>1, 3=>-8, -1=>6, -2=>pk);
julia> cbor_pk = CBOR.encode(cose);

# -- 3. Compose authenticatorData with all needed fields --
julia> rpId = "example.com";
julia> rpIdHash = SHA.sha256(Vector{UInt8}(rpId));     # 32 bytes
julia> flags = 0x41;                                   # User Present + attested
julia> signCount = UInt8[0,0,0,1];                     # Just a value
julia> aaguid = zeros(UInt8,16);                       # 16 bytes
julia> credId = rand(UInt8,16);                        # Some random id
julia> credIdLen = [UInt8(length(credId) >> 8), UInt8(length(credId)&0xff)]; # Big Endian
julia> authData = vcat(rpIdHash, flags, signCount, aaguid, credIdLen, credId, cbor_pk);

# -- 4. Prepare clientDataJSON and signature message --
julia> clientDataJSON = b"""{"type":"webauthn.create","challenge":"abc","origin":"https://example.com"}""";
julia> clientDataHash = SHA.sha256(clientDataJSON);
julia> msg = vcat(authData, clientDataHash);

# -- 5. Make the Ed25519 signature on the message --
julia> sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES);
julia> sl = Ref{UInt64}();
julia> Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk);

# -- 6. Build attStmt (the minimal self-attestation format) --
julia> attStmt = Dict("sig"=>sig, "alg"=>-8);

# -- 7. Now verify: This returns true! --
julia> verify_attestation_packed(attStmt, msg, authData)
true

# -- 8. Negative test: Tweak the sig, see a failure --
julia> sig2 = copy(sig); sig2[1] ⊻= 0xFF;
julia> attStmt_bad = Dict("sig"=>sig2, "alg"=>-8);
julia> verify_attestation_packed(attStmt_bad, msg, authData)
false
=#

"""
    verify_attestation_packed(attStmt::Dict, msg::Vector{UInt8},
        authData::Vector{UInt8}[, clientDataJSON::Vector{UInt8}])::Bool

Verify a WebAuthn `"packed"` attestation statement  
(e.g., self-attested Ed25519 / ECDSA / RSA, as used in device authentication).

On success, returns `true`; otherwise, returns `false`.  
For Ed25519 (OKP, alg -8), the signature must be over `SHA256(clientDataJSON)` 
(not the full `authData || SHA256(clientDataJSON)`).

# Examples

```jldoctest
julia> using WebAuthn, CBOR, Sodium, SHA

julia> pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES);

julia> sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES);

julia> Sodium.crypto_sign_keypair(pk, sk);

julia> cose = Dict(1=>1, 3=>-8, -1=>6, -2=>pk);

julia> cbor_pk = CBOR.encode(cose);

julia> rpId = "example.com";

julia> rpIdHash = SHA.sha256(Vector{UInt8}(rpId));

julia> flags = 0x41; signCount = UInt8[0,0,0,1]; aaguid = zeros(UInt8,16);

julia> credId = rand(UInt8,16); credIdLen = [UInt8(length(credId) >> 8), 
           UInt8(length(credId)&0xff)];

julia> authData = vcat(rpIdHash, flags, signCount, aaguid, credIdLen, 
           credId, cbor_pk);

julia> clientDataJSON = b\"\"\"{"type":"webauthn.create","challenge":"abc",
            "origin":"https://example.com"}\"\"\";

julia> clientDataHash = SHA.sha256(clientDataJSON);

julia> sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES);

julia> sl = Ref{UInt64}();

julia> Sodium.crypto_sign_detached(sig, sl, clientDataHash, 
            length(clientDataHash), sk);

julia> msg = vcat(authData, clientDataHash);

julia> attStmt = Dict("sig"=>sig, "alg"=>-8);

julia> verify_attestation_packed(attStmt, msg, authData)
true

julia> attStmt_bad = deepcopy(attStmt); attStmt_bad["sig"][1] ⊻= 0xFF;

julia> verify_attestation_packed(attStmt_bad, msg, authData)
false
```
"""
function verify_attestation_packed(attStmt::Dict, msg::Vector{UInt8},
    authData::Vector{UInt8})::Bool
    sig = Vector{UInt8}(attStmt["sig"])
    cose_alg = Int(attStmt["alg"])

    # Accept only the algorithms you implement
    if !(cose_alg in (-7, -257, -8))
        error("Unsupported packed alg $cose_alg")
    end
    if haskey(attStmt, "x5c")
        certs = attStmt["x5c"]::Vector{Vector{UInt8}}
        pubkey = extract_pubkey_from_der_raw(certs[1])
        if pubkey isa EC2PublicKey
            # FIX: HASH MSG!
            return verify_p256_signature_raw_xy(pubkey.x, pubkey.y,
                SHA.sha256(msg), sig)
        elseif pubkey isa RSAPublicKey
            return verify_rsa_signature_raw_ne(pubkey.n, pubkey.e,
                SHA.sha256(msg), sig)
        else
            error("Unsupported public key type from attestation cert")
        end
    else
        credpub = parse_credential_public_key(authData)
        msub = msg[length(authData)+1:end]
        if credpub isa EC2PublicKey
            # FIX: HASH msub!
            return verify_p256_signature_raw_xy(credpub.x, credpub.y,
                SHA.sha256(msub), sig)
        elseif credpub isa RSAPublicKey
            return verify_rsa_signature_raw_ne(credpub.n, credpub.e,
                SHA.sha256(msub), sig)
        elseif credpub isa OKPPublicKey
            return Sodium.crypto_sign_verify_detached(sig, msub,
                length(msub), credpub.x) == 0
        else
            error("Self-attestation only supported for EC2/RSA/OKP,
                got $(typeof(credpub))")
        end
    end
end

function verify_attestation_packed(attStmt::Dict, msg::Vector{UInt8},
    authData::Vector{UInt8}, clientDataJSON::Vector{UInt8})
    verify_attestation_packed(attStmt, msg, authData)
end