#=
Julia’s OpenSSL_jll v3.x failed to load PEM public keys (shows decoder "unsupported" error) because the artifact did not include the required ossl-modules/provider .so files (default.so, legacy.so, etc). These providers are required by OpenSSL 3.x to load, parse, and decode PEM or DER keys. No code, ccall, or Julia environment variable can work around it if the modules are missing from the artifact. Even explicit provider loading or setting OPENSSL_MODULES failed, because there was nothing for OpenSSL to load. The root cause is that the BinaryBuilder build script for OpenSSL_jll only installs libcrypto/libssl and not the providers; to fix, the ossl-modules directory must be bundled in the artifact. Until then, PEM/DER key operations in Julia with OpenSSL 3.x will fail; using system OpenSSL or OpenSSL_jll v1.1 or parsing COSE keys without PEM are the only workarounds for now.
=#


#chrome://settings/securityKeys

"""
    module WebAuthn

A Julia package for WebAuthn/FIDO2 credential registration
and authentication in web applications.

Supports all required cryptographic formats: CBOR/COSE, Ed25519 (OKP),
ECDSA (P-256), RSA public keys, base64url, and PEM export.
Utility functions simplify browser-challenge generation, and parsing and
verification of registration and authentication responses.
"""
module WebAuthn

using Base64, Random, CBOR, JSON3, SHA, OpenSSL_jll, Dates, UUIDs, Sodium

include("base64url.jl")
include("challenge.jl")
include("cose_keys.jl")
include("authdata.jl")
include("option_builders.jl")
include("clientdata.jl")
include("signature.jl")
include("attestation.jl")
include("assets.jl")

end  # module WebAuthn
