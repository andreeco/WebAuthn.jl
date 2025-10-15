@testset "authenticatorData parsing" begin
    # Load a real, valid EC2 P-256 public key 
    pem = load_vector("vectors_ec2_packed", "pubkey.pem")
    x, y = parse_ec_pem_xy(pem)
    @test length(x) == 32
    @test length(y) == 32

    # Compose COSE_Key in CBOR encoding 
    pk_cbor = CBOR.encode(Dict(1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y))

    # FIDO2/WebAuthn authenticatorData dummy:
    rp_id_hash = rand(UInt8, 32)      
    # UP flag set + AT flag set
    flags = 0x41                      
    sign_count = [0x00, 0x00, 0x00, 0x05]
    # Random AAGUID, 16 bytes
    aaguid = rand(UInt8, 16)    
    credid = rand(UInt8, 32)
    credlen = [UInt8((length(credid) >> 8) & 0xff), UInt8(length(credid) & 0xff)]

    # Compose correct authenticatorData buffer
    # [0:31] rpIdHash | [32] flags | [33:36] signCount | 
    # [37:52] aaguid | [53:54] credlen | [..] credid | [..] pk_cbor
    authData = vcat(
        rp_id_hash,
        flags,
        sign_count,
        aaguid,
        credlen,
        credid,
        pk_cbor
    )
    pkbytes = extract_credential_public_key(authData)
    @test pkbytes == pk_cbor   # Field-extraction checks full slice (CBOR map)

    key = parse_credential_public_key(authData)
    @test isa(key, WebAuthn.WebAuthnPublicKey)
end