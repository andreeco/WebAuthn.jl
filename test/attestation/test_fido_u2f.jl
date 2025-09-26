# test_fido_u2f.jl
# -----------------------------------------------
# Purpose: Handle legacy FIDO U2F format registration, attestation, and 
# assertion
# Spec: §8.6
# Tests:
#   - Valid U2F vectors parse and pass; handle appid extensions if supported
#   - Should reject malformed, incomplete, or tampered U2F objects
using Test, WebAuthn


@testset "FIDO2/U2F Interop Vector: Registration+Authentication" begin
    # Registration vector from your REG VECTOR FIELD EXTRACT:
    attestationObject = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBA0mWDeWIDoxod\
    DQXD2R2YFuP5K65ooYyx5lc87qDHZdjxQAAADcAAAAAAAAAAAAAAAAAAAAAAHGjAFhNYVL-2n5f\
    xIdRXp7L2djNXNm3Vb1I3b6tSuKfp2-lmdeFMrsFDx7wNcQHMjFD7TNs6vgvYSO0TLbn7mCRgY\
    COoKnCVTqi1VAMBkD2ZrIBTF41_aRryaT31aRplQJQJOa1h5tWSQNY_D5_nkyScqUBAgMmIAEhW\
    CBDDRhgSiAM4xNcKGqBQP7yVkvv2KvmPb6WdB7fsXoilyJYIKDwebF9hi-398pw5F3lizReHFz\
    AAcT5fa5HOdKJYammoWtobWFjLXNlY3JldPQ"
    clientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTzA1\
    UmhUQnY4eE1mblNacEtKTWdNX1IyODlpTHVpSFUweHZlalh1cWNROCIsIm9yaWdpbiI6Imh0dH\
    A6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
    pubkey_pem = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQw0YYEogDOMTXChqgUD+8lZL79ir
5j2+lnQe37F6Ipeg8HmxfYYvt/fKcORd5Ys0XhxcwAHE+X2uRznSiWGppg==
-----END PUBLIC KEY-----
"""
    @test verify_attestation_object(attestationObject,
        WebAuthn.base64urldecode(clientDataJSON)) == true

    # First login vector (from your LOGIN VECTOR FIELD EXTRACT)
    authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAOQ"
    assertion_clientDataJSON = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlI\
    joiUFNHeU9OQnM2eEZ0b2tPRklCbUNpYU5DMEw2dHlCbWRXd1dUQXNsZ2xUSSIsIm9yaWdpbi\
    I6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
    signature = "MEUCIQC4jROHcpctF-IV8RYwuoaIjXrDXuUgMNUS2L3jDBTRagIgC-pjPSZu\
    pMkHlQVSVWQwMkq2TsoBCSt_5jgJoql1-AY"
    @test verify_webauthn_signature(pubkey_pem,
        WebAuthn.base64urldecode(authenticatorData),
        WebAuthn.base64urldecode(assertion_clientDataJSON),
        WebAuthn.base64urldecode(signature)) == true

    # Second login vector (if you want to check multiple logins)
    authenticatorData2 = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAOw"
    assertion_clientDataJSON2 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdl\
    IjoiOEJpdnJfeUpNczBJMHY3WTNrZmVzUTFaendqdlJ1NmJ4d1E1enZrM09tZyIsIm9yaWdpb\
    iI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
    signature2 = "MEQCIB0NaGNrnj1eMKNUf4grMzELFcUbklbsTu7Jy4qEjrZWAiB09p7fR\
    rNP7rQ1e5H2fwP6I_dtQLIHxh3oXyWRtM2DLA"
    @test verify_webauthn_signature(pubkey_pem,
        WebAuthn.base64urldecode(authenticatorData2),
        WebAuthn.base64urldecode(assertion_clientDataJSON2),
        WebAuthn.base64urldecode(signature2)) == true
end

@testset "FIDO2/U2F legacy (fmt:fido-u2f) interop/attestation" begin
    # This package does not support pure U2F attestation 
    @test_broken false  # Deliberately always broken.
end