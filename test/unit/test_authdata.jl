# test_authdata.jl
# -------------------------------------
# SPEC_ID: §6.1-AuthenticatorData-Structure
#   Authenticator data byte layout and field offsets.
# SPEC_ID: §6.1-rpIdHash
#   First 32 bytes = SHA-256 hash of RP ID.
# SPEC_ID: §6.1-Flags-UP
#   Flags byte at offset 33, UP (bit 0) must be present.
# SPEC_ID: §6.1-signCount
#   4-byte unsigned int at offset 34–37.
# SPEC_ID: §6.5.1-AttestedCredentialData
#   AttestedCredentialData structure presence, length, and parsing.
# SPEC_ID: §7.1-Registration-Extract-PublicKey
#   Extraction of COSE_Key from attestedCredentialData.
# SPEC_ID: §2.2-Authenticator-API
# SPEC_ID: §5.2.1-getAuthenticatorData
@testset "authenticatorData parsing" begin
    # Load a real, valid EC2 P-256 public key 
    # (SPEC_ID: §3-COSE-EC2-crv-x-y-Length)
    pem = load_vector("vectors_ec2_packed", "pubkey.pem")
    x, y = parse_ec_pem_xy(pem)
    @test length(x) == 32             # SPEC_ID: §3-COSE-EC2-crv-x-y-Length
    @test length(y) == 32             # SPEC_ID: §3-COSE-EC2-crv-x-y-Length

    # Compose COSE_Key in CBOR encoding 
    # (SPEC_ID: §5.8.5-COSEAlgorithmIdentifier)
    pk_cbor = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y))

    # FIDO2/WebAuthn authenticatorData dummy:
    # In "real" test: SHA256(RP ID), see §6.1-rpIdHash
    rp_id_hash = rand(UInt8, 32)      
    # UP flag set + AT flag set (SPEC_ID: §6.1-Flags-UP,
    # SPEC_ID:  §6.1-Flags-ED-AT)
    # SPEC_ID: §6.1-Flags-BE
    flags = 0x41                      
    # SPEC_ID: §6.1-signCount
    sign_count = [0x00, 0x00, 0x00, 0x05]
    # Random AAGUID, 16 bytes (SPEC_ID: §6.5.1-AttestedCredentialData)
    aaguid = rand(UInt8, 16)    
    # SPEC_ID: §4-CredentialID-Length-Entropy      
    credid = rand(UInt8, 32)
    credlen = [UInt8((length(credid) >> 8) & 0xff), UInt8(length(credid) & 0xff)]

    # Compose correct authenticatorData buffer
    # [0:31] rpIdHash | [32] flags | [33:36] signCount | 
    # [37:52] aaguid | [53:54] credlen | [..] credid | [..] pk_cbor
    authData = vcat(
        rp_id_hash,                  # SPEC_ID: §6.1-rpIdHash
        flags,                       # SPEC_ID: §6.1-Flags-UP, §6.1-Flags-ED-AT
        sign_count,                  # SPEC_ID: §6.1-signCount
        aaguid,                      # SPEC_ID: §6.5.1-AttestedCredentialData
        credlen,                     # SPEC_ID: §6.5.1-AttestedCredentialData
        credid,                      # SPEC_ID: §6.5.1-AttestedCredentialData
        pk_cbor                      # SPEC_ID: §7.1-Registration-Extract-PublicKey
    )

    # SPEC_ID: §7.1-Registration-Extract-PublicKey
    pkbytes = extract_credential_public_key(authData)
    @test pkbytes == pk_cbor   # Field-extraction checks full slice (CBOR map)

    # SPEC_ID: §5.8.5-COSEAlgorithmIdentifier
    # SPEC_ID: §6.3.2-authenticatorMakeCredential
    key = parse_credential_public_key(authData)
    @test isa(key, WebAuthn.WebAuthnPublicKey)
end