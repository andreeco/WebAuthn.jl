export verify_webauthn_signature

"""
    verify_webauthn_signature(key_or_pem, authenticatorData, clientDataJSON, 
        signature)::Bool

Verify a WebAuthn assertion signature for the given public key or PEM.

# Examples

```jldoctest
julia> using WebAuthn, Sodium, SHA

julia> pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES);

julia> sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES);

julia> Sodium.crypto_sign_keypair(pk, sk);

julia> key = OKPPublicKey(pk, -8, 6);

julia> ad = rand(UInt8, 37);

julia> cdj = rand(UInt8, 32);

julia> msg = vcat(ad, SHA.sha256(cdj));

julia> sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES);

julia> sl = Ref{Culonglong}();

julia> Sodium.crypto_sign_detached(sig, sl, msg, length(msg), sk);

julia> valid = verify_webauthn_signature(key, ad, cdj, sig)
true
```

See also: [`cose_key_to_pem`](@ref) and [`parse_assertion`](@ref).
"""
function verify_webauthn_signature end

function verify_webauthn_signature(key::OKPPublicKey, ad::Vector{UInt8},
    cdj::Vector{UInt8}, sig::Vector{UInt8})::Bool
    msg = vcat(ad, SHA.sha256(cdj))
    Sodium.crypto_sign_verify_detached(sig, msg, length(msg), key.x) == 0
end

function verify_webauthn_signature(key::EC2PublicKey,
    ad::Vector{UInt8},
    cdj::Vector{UInt8},
    sig::Vector{UInt8})::Bool
    msg = vcat(ad, SHA.sha256(cdj))
    digest = SHA.sha256(msg)
    return verify_p256_signature_raw_xy(key.x, key.y, digest, sig)
end

function verify_webauthn_signature(key::RSAPublicKey, ad::Vector{UInt8},
    cdj::Vector{UInt8}, sig::Vector{UInt8})::Bool
    msg = vcat(ad, SHA.sha256(cdj))
    msg_hash = SHA.sha256(msg)
    verify_rsa_signature_raw_ne(key.n, key.e, msg_hash, sig)
end

function verify_webauthn_signature(pubkey_pem::AbstractString,
    ad::Vector{UInt8}, cdj::Vector{UInt8}, sig::Vector{UInt8})::Bool

    # Compute the exact message per WebAuthn: 
    # authenticatorData || SHA256(clientDataJSON)
    msg_hash = SHA.sha256(vcat(ad, SHA.sha256(cdj)))

    # 1) Try EC2 (ES256)
    try
        x, y = parse_ec_pem_xy(pubkey_pem)
        return verify_p256_signature_raw_xy(x, y, msg_hash, sig)
    catch
        # fall through to RSA/OKP
    end

    # 2) Try RSA (RS256)
    try
        n, e = parse_rsa_pem_ne(pubkey_pem)
        # With RSA_verify, the digest must already be SHA256
        return verify_rsa_signature_raw_ne(n, e, msg_hash, sig)
    catch
        # fall through to OKP
    end

    # 3) Try Ed25519 (OKP)
    try
        x = parse_ed25519_pem_x(pubkey_pem)
        # Sodium expects raw message for EdDSA, but WebAuthn signs 
        # authenticatorData || SHA256(cdj)
        # However for Ed25519 we sign the raw message, not its hash
        full_msg = vcat(ad, SHA.sha256(cdj))
        return Sodium.crypto_sign_verify_detached(
            sig, full_msg, length(full_msg), x) == 0
    catch
        # nothing left
    end

    return false
end



#=
# Dont go for this!!
function verify_webauthn_signature(pubkey_pem::AbstractString,
    ad::Vector{UInt8}, cdj::Vector{UInt8}, sig::Vector{UInt8})::Bool
    msg = vcat(ad, SHA.sha256(cdj))
    msg_hash = SHA.sha256(msg)
    tmp = tempname() * ".pem"
    open(tmp, "w") do io
        write(io, pubkey_pem)
    end
    pkctx = MbedTLS.PKContext()
    ok = false
    try
        MbedTLS.parse_public_keyfile!(pkctx, tmp)
        ok = MbedTLS.verify(pkctx, MbedTLS.MD_SHA256, msg_hash, sig) == 0
    catch
        ok = false
    finally
        rm(tmp, force=true)
    end
    ok
end
=#

function verify_webauthn_signature(key::WebAuthnPublicKey, ad::Vector{UInt8},
    cdj::Vector{UInt8}, sig::Vector{UInt8})::Bool
    error("Unsupported key type for WebAuthn signature: $(typeof(key))")
end

"""
    verify_p256_signature_raw_xy(x, y, digest, sig)::Bool

Verify a P-256 ECDSA sig with OpenSSL using raw pubkey XY, SHA256 digest, 
and DER-encoded signature.

# Examples

```jldoctest
julia> using WebAuthn, SHA

julia> x = UInt8[
           0x7d, 0xf1, 0xb2, 0x85, 0x1d, 0xdc, 0x04, 0x29,
           0xdf, 0x71, 0xbd, 0x49, 0x9f, 0xea, 0x1d, 0xef,
           0xca, 0x63, 0x4c, 0x5c, 0xbe, 0x8e, 0xaa, 0xa5,
           0xcd, 0x3b, 0xa6, 0x65, 0xb7, 0xba, 0x3e, 0x32
       ];

julia> y = UInt8[
           0x6e, 0x33, 0x03, 0x54, 0xd9, 0x5f, 0x0d, 0xb7,
           0x28, 0x69, 0xec, 0x9a, 0x47, 0x82, 0x99, 0xe4,
           0xe9, 0x34, 0x44, 0xe4, 0x8d, 0x40, 0x8f, 0xbe,
           0xa1, 0x61, 0xf9, 0x3a, 0x4f, 0xd2, 0x14, 0xb8
       ];

julia> msg    = b"test message";

julia> digest = SHA.sha256(msg);

julia> sig = UInt8[
           0x30, 0x45, 0x02, 0x21, 0x00, 0xa9, 0xe7, 0x2a,
           0x18, 0x6a, 0xe2, 0xa3, 0x5d, 0x7a, 0x34, 0xa2,
           0x60, 0xef, 0xff, 0x36, 0x27, 0xbb, 0x59, 0x31,
           0xf9, 0xe3, 0xdb, 0xe5, 0xf8, 0x0a, 0xa2, 0xff,
           0x3f, 0xad, 0x2e, 0x3c, 0x79, 0x02, 0x20, 0x74,
           0x24, 0x4a, 0xb1, 0x19, 0xf2, 0x70, 0x4f, 0xa2,
           0x62, 0xdc, 0x87, 0x6c, 0x6b, 0xeb, 0xda, 0x77,
           0xe1, 0x5a, 0x5a, 0x13, 0xb9, 0xec, 0x87, 0x4e,
           0x29, 0x4b, 0x25, 0x95, 0x83, 0xc9, 0xdf];

julia> WebAuthn.verify_p256_signature_raw_xy(x, y, digest, sig)
true

julia> sig2 = copy(sig); sig2[1] ⊻= 0xFF;

julia> WebAuthn.verify_p256_signature_raw_xy(x, y, digest, sig2)
false
```
"""
function verify_p256_signature_raw_xy(x::Vector{UInt8},
    y::Vector{UInt8},
    digest::Vector{UInt8},
    sig::Vector{UInt8})::Bool

    NID_P256 = 415
    NID_sha256 = 672

    ec_key = ccall((:EC_KEY_new_by_curve_name, OpenSSL_jll.libcrypto),
        Ptr{Cvoid}, (Cint,), NID_P256)
    ec_key == C_NULL && error("Failed to create EC_KEY")

    GC.@preserve x y digest sig begin
        bn_x = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(x),
            Cint(length(x)), C_NULL)
        bn_y = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(y),
            Cint(length(y)), C_NULL)
        bn_x == C_NULL && (ccall((:EC_KEY_free, OpenSSL_jll.libcrypto),
            Cvoid, (Ptr{Cvoid},), ec_key);
        error("Failed to create bn_x"))
        bn_y == C_NULL && (ccall((:BN_free, OpenSSL_jll.libcrypto),
            Cvoid, (Ptr{Cvoid},), bn_x);
        ccall((:EC_KEY_free,
                OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), ec_key);
        error("Failed to create bn_y"))

        success = false
        try
            # 3) Attach coords
            ok = ccall((:EC_KEY_set_public_key_affine_coordinates,
                    OpenSSL_jll.libcrypto),
                Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                ec_key, bn_x, bn_y)
            ok != 1 && error("Failed to set EC coords")

            # 4) ECDSA_verify
            ret = ccall((:ECDSA_verify, OpenSSL_jll.libcrypto), Cint,
                (Cint, Ptr{UInt8}, Cint, Ptr{UInt8}, Cint, Ptr{Cvoid}),
                NID_sha256,
                pointer(digest), Cint(length(digest)),
                pointer(sig), Cint(length(sig)),
                ec_key)
            success = (ret == 1)
        finally
            ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), bn_x)
            ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), bn_y)
            ccall((:EC_KEY_free, OpenSSL_jll.libcrypto), Cvoid,
                (Ptr{Cvoid},), ec_key)
        end
    end # GC.@preserve
    return success
end

"""
    verify_rsa_signature_raw_ne(n, e, digest, sig)::Bool

Verify an RSA PKCS1v1.5/SHA256 signature using raw modulus and exponent buffers, 
with everything in memory.

# Examples

```jldoctest
julia> using WebAuthn, SHA, Test

julia> n = UInt8[0xc8,0xac,0xb4,0xd0,0x1c,0x87,0x78,0x45,0x1d,0xcc,0xfa,
                 0xee,0x0a,0xe1,0x38,0xb4,0x12,0x71,0xf2,0x85,0x9d,0x00,
                 0xb1,0xf8,0x01,0x74,0x01,0xb9,0xcc,0x8f,0x02,0xda,0x6b,
                 0xa3,0x7a,0xe3,0xd8,0x35,0x00,0x63,0x52,0x16,0x4e,0xfc,
                 0xe3,0x8b,0xd0,0x88,0x8e,0xa8,0x03,0x6c,0x56,0x38,0x1f,
                 0x85,0xfd,0xf4,0xc0,0xa4,0x5b,0x6c,0x3f,0x0d];

julia> e = UInt8[0x01, 0x00, 0x01];

julia> msg = b"hello RSA";

julia> digest = SHA.sha256(msg);

julia> sig = UInt8[0x15,0xe4,0xed,0xd0,0x0a,0xe1,0x62,0xda,0xe5,0x84,0xb6,
                   0x9c,0x91,0x96,0x5e,0xba,0xa8,0x3a,0x01,0x55,0xc5,0x6e,
                   0x06,0xce,0xd5,0xd1,0x02,0x49,0x17,0x4c,0xb4,0xbf,0x36,
                   0x77,0x88,0x48,0x46,0x59,0x2e,0xd9,0xac,0x3e,0xcd,0x83,
                   0x69,0xab,0x46,0x8a,0xfe,0xa8,0xd0,0xee,0x1f,0x9c,0xfd,
                   0xe1,0xd9,0x03,0x57,0x70,0x34,0xe5,0x80,0xeb];

julia> WebAuthn.verify_rsa_signature_raw_ne(n, e, digest, sig)
true

julia> sig_bad = copy(sig);

julia> sig_bad[1] ⊻= 0xFF;

julia> WebAuthn.verify_rsa_signature_raw_ne(n, e, digest, sig_bad)
false
```
"""
function verify_rsa_signature_raw_ne(n::Vector{UInt8}, e::Vector{UInt8},
    digest::Vector{UInt8}, sig::Vector{UInt8})::Bool

    NID_sha256 = 672

    rsa = ccall((:RSA_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, ())
    rsa == C_NULL && error("Failed to allocate RSA")

    GC.@preserve n e digest sig begin
        bn_n = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(n), Cint(length(n)),
            C_NULL)
        bn_e = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}), pointer(e), Cint(length(e)),
            C_NULL)
        bn_n == C_NULL && (ccall((:RSA_free, OpenSSL_jll.libcrypto), Cvoid,
            (Ptr{Cvoid},), rsa);
        error("Failed to create bn_n"))
        bn_e == C_NULL && (ccall((:BN_free, OpenSSL_jll.libcrypto), Cvoid,
            (Ptr{Cvoid},), bn_n);
        ccall((:RSA_free, OpenSSL_jll.libcrypto), Cvoid,
            (Ptr{Cvoid},), rsa);
        error("Failed to create bn_e"))

        success = false
        try
            ok = ccall((:RSA_set0_key, OpenSSL_jll.libcrypto), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                rsa, bn_n, bn_e, C_NULL)
            ok != 1 && error("Failed to set RSA key")

            ret = ccall((:RSA_verify, OpenSSL_jll.libcrypto), Cint,
                (Cint, Ptr{UInt8}, Cuint, Ptr{UInt8}, Cuint, Ptr{Cvoid}),
                NID_sha256,
                pointer(digest), Cuint(length(digest)),
                pointer(sig), Cuint(length(sig)),
                rsa)
            success = (ret == 1)
        finally
            ccall((:RSA_free, OpenSSL_jll.libcrypto), Cvoid,
                (Ptr{Cvoid},), rsa)
        end
    end
    return success
end