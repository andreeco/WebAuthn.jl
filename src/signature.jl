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

"""
Avoid this too?
"""
function verify_webauthn_signature(pubkey_pem::AbstractString,
    ad::Vector{UInt8}, cdj::Vector{UInt8}, sig::Vector{UInt8})::Bool

    # Compute the exact message per WebAuthn: authenticatorData || SHA256(clientDataJSON)
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
        # Sodium expects raw message for EdDSA, but WebAuthn signs authenticatorData || SHA256(cdj)
        # However for Ed25519 we sign the raw message, not its hash
        full_msg = vcat(ad, SHA.sha256(cdj))
        return Sodium.crypto_sign_verify_detached(sig, full_msg, length(full_msg), x) == 0
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

```bash
openssl ecparam -genkey -name prime256v1 -noout -out key.pem
openssl ec -in key.pem -pubout -out pubkey.pem
openssl ec -in key.pem -noout -text
echo -n "test message" > msg.txt
openssl dgst -sha256 -sign key.pem -out sig.der msg.txt
```

```julia
using OpenSSL_jll, SHA, Test

# Copy your x and y (in hex) as UInt8 arrays BELOW, 32 bytes each:
x = UInt8[
    0x78,0x7e,0x03,0x96,0xa4,0x17,0x8e,0x1f,0x1a,0x9c,0x9c,0xa0,0x2e,0x9d,0x52,0x46,
    0x22,0x67,0xff,0x81,0x82,0x46,0xd4,0x19,0x17,0x26,0x4f,0xec,0x1e,0xda,0x3b,0x71
]
y = UInt8[
    0x86,0x58,0x9b,0xd6,0xcb,0xb5,0x89,0x60,0x82,0xb4,0xca,0x6f,0xd0,0x10,0xa6,0x0f,
    0x14,0x0f,0x37,0x53,0x6a,0x9e,0x3e,0x8a,0x0e,0x2d,0x24,0x6f,0x85,0x58,0xb5,0x2c
]

# Your message—MUST match what you signed!
msg = b"test message" # Or, open/read("msg.txt")

# Digest with SHA256 as required by ECDSA_verify(type=0)
digest = SHA.sha256(msg)

# Your sig: read the DER-encoded sig file as UInt8 array:
sig = read("sig.der")

@testset "P-256 ECDSA Verification with Raw XY" begin
    @test verify_p256_signature_raw_xy(x, y, digest, sig)
    # Negative test (wrong sig)
    sig_bad = sig .⊻ 0xFF
    @test !verify_p256_signature_raw_xy(x, y, digest, sig_bad)
end

println("All tests completed!")
```
"""
function verify_p256_signature_raw_xy(x::Vector{UInt8},
                                     y::Vector{UInt8},
                                     digest::Vector{UInt8},
                                     sig::Vector{UInt8})::Bool

    # 1) Create new EC_KEY for curve P-256
    NID_P256 = 415  # NID_X9_62_prime256v1
    ec_key = ccall((:EC_KEY_new_by_curve_name, OpenSSL_jll.libcrypto),
                   Ptr{Cvoid}, (Cint,), NID_P256)
    ec_key == C_NULL && error("Failed to create EC_KEY")

    # 2) Build BIGNUMs for X, Y
    bn_x = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
                 (Ptr{UInt8}, Cint, Ptr{Cvoid}),
                 pointer(x), length(x), C_NULL)
    bn_y = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid},
                 (Ptr{UInt8}, Cint, Ptr{Cvoid}),
                 pointer(y), length(y), C_NULL)
    bn_x == C_NULL && error("Failed to create bn_x")
    bn_y == C_NULL && error("Failed to create bn_y")

    # 3) Attach coordinates to EC_KEY
    ok = ccall((:EC_KEY_set_public_key_affine_coordinates, OpenSSL_jll.libcrypto),
               Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
               ec_key, bn_x, bn_y)
               
    ok != 1 && error("Failed to set EC public key coordinates")

    # 4) Perform ECDSA_verify: pass NID_sha256 so OpenSSL treats 'digest' as SHA-256
    NID_sha256 = 672
    ret = ccall((:ECDSA_verify, OpenSSL_jll.libcrypto), Cint,
                (Cint, Ptr{UInt8}, Cint, Ptr{UInt8}, Cint, Ptr{Cvoid}),
                NID_sha256,
                pointer(digest), length(digest),
                pointer(sig),    length(sig),
                ec_key)

    # 5) Clean up
    ccall((:EC_KEY_free,  OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), ec_key)
    ccall((:BN_free,      OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), bn_x)
    ccall((:BN_free,      OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), bn_y)

    return ret == 1
end

"""
    verify_rsa_signature_raw_ne(n, e, digest, sig)::Bool

Verify an RSA PKCS1v1.5/SHA256 signature using raw modulus and exponent buffers, 
with everything in memory.

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:512 -out testrsa.pem
openssl rsa -in testrsa.pem -pubout -outform PEM -out testrsapub.pem
openssl rsa -pubin -in testrsapub.pem -text -noout > modulus.txt
echo -n "hello RSA" > msg.txt
openssl dgst -sha256 -sign testrsa.pem -out sig.bin msg.txt
```

```julia
using OpenSSL_jll, SHA, Test

n = UInt8[
    0x00, 0xc8, 0xac, 0xb4, 0xd0, 0x1c, 0x87, 0x78, 0x45, 0x1d, 0xcc, 0xfa, 
    0xee, 0x0a, 0xe1, 0x38, 0xb4, 0x12, 0x71, 0xf2, 0x85, 0x9d, 0x00, 0xb1, 
    0xf8, 0x01, 0x74, 0x01, 0xb9, 0xcc, 0x8f, 0x02, 0xda, 0x6b, 0xa3, 0x7a, 
    0xe3, 0xd8, 0x35, 0x00, 0x63, 0x52, 0x16, 0x4e, 0xfc, 0xe3, 0x8b, 0xd0, 
    0x88, 0x8e, 0xa8, 0x03, 0x6c, 0x56, 0x38, 0x1f, 0x85, 0xfd, 0xf4, 0xc0,
    0xa4, 0x5b, 0x6c, 0x3f, 0x0d]
e = UInt8[0x01, 0x00, 0x01]

msg = b"hello RSA"
digest = SHA.sha256(msg)

sig = UInt8[0x15, 0xe4, 0xed, 0xd0, 0x0a, 0xe1, 0x62, 0xda, 0xe5, 0x84, 0xb6, 
          0x9c, 0x91, 0x96, 0x5e, 0xba, 0xa8, 0x3a, 0x01, 0x55, 0xc5, 0x6e, 
          0x06, 0xce, 0xd5, 0xd1, 0x02, 0x49, 0x17, 0x4c, 0xb4, 0xbf, 0x36, 
          0x77, 0x88, 0x48, 0x46, 0x59, 0x2e, 0xd9, 0xac, 0x3e, 0xcd, 0x83, 
          0x69, 0xab, 0x46, 0x8a, 0xfe, 0xa8, 0xd0, 0xee, 0x1f, 0x9c, 0xfd, 
          0xe1, 0xd9, 0x03, 0x57, 0x70, 0x34, 0xe5, 0x80, 0xeb]

@testset "RSA verify (all in memory, OpenSSL_jll)" begin
    @test verify_rsa_signature_raw_ne(n, e, digest, sig)
    sig_bad = copy(sig)
    sig_bad[1] ⊻= 0xFF
    @test !verify_rsa_signature_raw_ne(n, e, digest, sig_bad)
end

println("RSA in-memory signature verify demo completed.")
```
"""
function verify_rsa_signature_raw_ne(n::Vector{UInt8}, e::Vector{UInt8}, 
    digest::Vector{UInt8}, sig::Vector{UInt8})::Bool
    rsa = ccall((:RSA_new, OpenSSL_jll.libcrypto), Ptr{Cvoid}, ())
    bn_n = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid}, 
    (Ptr{UInt8}, Cint, Ptr{Cvoid}),
        pointer(n), length(n), C_NULL)
    bn_e = ccall((:BN_bin2bn, OpenSSL_jll.libcrypto), Ptr{Cvoid}, 
    (Ptr{UInt8}, Cint, Ptr{Cvoid}),
        pointer(e), length(e), C_NULL)
    ccall((:RSA_set0_key, OpenSSL_jll.libcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), rsa, bn_n, 
        bn_e, C_NULL)
    NID_sha256 = 672
    ret = ccall((:RSA_verify, OpenSSL_jll.libcrypto), Cint,
        (Cint, Ptr{UInt8}, Cuint, Ptr{UInt8}, Cuint, Ptr{Cvoid}),
        NID_sha256,
        pointer(digest), length(digest),
        pointer(sig), length(sig),
        rsa)
    ccall((:RSA_free, OpenSSL_jll.libcrypto), Cvoid, (Ptr{Cvoid},), rsa)
    return ret == 1
end