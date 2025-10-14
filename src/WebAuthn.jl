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

@warn "The package is currently not production ready and needs review."

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
