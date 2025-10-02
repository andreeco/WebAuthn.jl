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
    try
        attobj = parse_attestation_object(attObj_b64)
        fmt = String(attobj["fmt"])
        authData = attobj["authData"]::Vector{UInt8}
        clientDataHash = SHA.sha256(clientDataJSON)
        msg = vcat(authData, clientDataHash)
        if fmt == "none"
            (haskey(attobj, "attStmt") && length(attobj["attStmt"]) != 0) &&
                error("attStmt for format 'none' MUST be empty ({}), got: 
                $(attobj["attStmt"])")
            return true
        elseif fmt == "packed"
            return verify_attestation_packed(attobj["attStmt"], 
            msg, authData, clientDataJSON)
        else
            error("Unsupported attestation format: $fmt")
        end
    catch e
        @debug "verify_attestation_object failed: $e"
        return false
    end
end

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

    if !(cose_alg in (-7, -257, -8))
        error("Unsupported packed alg $cose_alg")
    end

    if haskey(attStmt, "x5c")
    certs = attStmt["x5c"]
    if !(certs isa AbstractVector) || isempty(certs)
        throw(ArgumentError(
            "attStmt[\"x5c\"] must be a non-empty vector of certificates"))
    end
    cert_der = certs[1]
    pubkey_pem = extract_pubkey_pem_from_der(cert_der)
    if pubkey_pem === nothing
        @debug "extract_pubkey_pem_from_der could not extract a public key"
        return false
    end
        cert_der = certs[1]
        pubkey_pem = extract_pubkey_pem_from_der(cert_der)

        if cose_alg == -7   # P-256
            x, y = parse_ec_pem_xy(pubkey_pem)
            return verify_p256_signature_raw_xy(x, y, SHA.sha256(msg), sig)
        elseif cose_alg == -257  # RSA
            n, e = parse_rsa_pem_ne(pubkey_pem)
            return verify_rsa_signature_raw_ne(n, e, SHA.sha256(msg), sig)
        elseif cose_alg == -8    # Ed25519
            x = parse_ed25519_pem_x(pubkey_pem)
            return Sodium.crypto_sign_verify_detached(
                sig, msg, length(msg), x) == 0
        else
            error("Unsupported algorithm in packed/x5c: $cose_alg")
        end
    else
        credpub = parse_credential_public_key(authData)
        msub = msg[length(authData)+1:end]

        if credpub isa EC2PublicKey
            return verify_p256_signature_raw_xy(credpub.x, credpub.y,
                SHA.sha256(msub), sig)
        elseif credpub isa RSAPublicKey
            return verify_rsa_signature_raw_ne(credpub.n, credpub.e,
                SHA.sha256(msub), sig)
        elseif credpub isa OKPPublicKey
            return Sodium.crypto_sign_verify_detached(sig, msub,
                length(msub),
                credpub.x) == 0
        else
            error("Self-attestation only supported for EC2/RSA/OKP, got $(
            typeof(credpub))")
        end
    end
end

function verify_attestation_packed(attStmt::Dict, msg::Vector{UInt8},
    authData::Vector{UInt8}, clientDataJSON::Vector{UInt8})
    verify_attestation_packed(attStmt, msg, authData)
end