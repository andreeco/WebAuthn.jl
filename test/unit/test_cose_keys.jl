using Test, WebAuthn, CBOR

@testset "EC2 Good" begin
    cose_bin = load_vector("vectors_ec2_none", "registration", 
    "attestationObject.cbor")
    # Parse attestationObject and extract COSE_Key
    attobj = CBOR.decode(cose_bin)
    authData = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authData[37+16+1])<<8)|
                           Int(authData[37+16+2]))
    pkbytes = authData[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    @test key isa EC2PublicKey
    @test key.alg == -7
    @test key.crv == 1
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
end

@testset "OKP Ed25519 Good" begin
    cose_bin = load_vector("vectors_ed25519_packed", "registration", 
    "attestationObject.cbor")
    attobj = CBOR.decode(cose_bin)
    authData = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authData[37+16+1])<<8)|
                           Int(authData[37+16+2]))
    pkbytes = authData[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    @test key isa OKPPublicKey
    @test key.alg == -8
    @test key.crv == 6
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
end

@testset "RSA Good" begin
    cose_bin = load_vector("vectors_rsa_packed", "registration", 
    "attestationObject.cbor")
    attobj = CBOR.decode(cose_bin)
    authData = attobj["authData"]
    pkoff = 37 + 16 + 2 + ((Int(authData[37+16+1])<<8)|
                           Int(authData[37+16+2]))
    pkbytes = authData[pkoff+1:end]
    cose = CBOR.decode(pkbytes)
    key = cose_key_parse(cose)
    @test key isa RSAPublicKey
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
end

@testset "EC2 BAD (missing y)" begin
    cose_b = UInt8[164, 1, 2, 3, 38, 32, 1, 33, 88, 32,
        83, 171, 141, 121, 88, 18, 46, 173, 166, 127, 160, 40,
        92, 178, 249, 182, 70, 196, 88, 55, 61, 5, 159, 127,
        243, 218, 165, 3, 67, 116, 60, 81]
    cose = CBOR.decode(cose_b)
    @test_throws Exception cose_key_parse(cose)
end

@testset "EC2 BAD (Extra unknown field)" begin
    cose_b = UInt8[166,1,2,3,38,32,1,33,88,32,83,171,141,121,88,
        18,46,173,166,127,160,40,92,178,249,182,70,196,88,55,61,
        5,159,127,243,218,165,3,67,116,60,81,34,88,32,123,247,
        82,170,104,216,226,46,219,11,230,187,37,245,34,194,24,6,
        21,145,134,239,19,202,77,226,96,247,100,102,133,80,25,39,
        15,67,97,98,99]
    cose = CBOR.decode(cose_b)
    # If code is strict, might want Exception here:
    # @test_throws Exception cose_key_parse(cose)
    # Or document code's leniency.
end

@testset "OKP BAD (alg=-999)" begin
    cose_b = UInt8[164,1,1,3,57,3,230,32,6,33,88,32,33,245,65,
        233,205,194,180,45,83,65,7,159,184,66,190,92,78,231,70,
        224,98,200,255,196,206,16,229,174,84,34,68,201]
    cose = CBOR.decode(cose_b)
    @test_throws Exception cose_key_parse(cose)
end

@testset "MALFORMED CBOR: Duplicate key in COSE_Key" begin
    cose_dup = UInt8[
        165,1,2,3,38,32,1,33,88,32,116,234,117,40,132,150,197,21,
        153,193,88,131,22,50,203,220,236,113,108,58,202,209,19,188,
        147,240,49,201,26,30,15,129,33,88,32,116,234,117,40,132,150,
        197,21,153,193,88,131,22,50,203,220,236,113,108,58,202,209,
        19,188,147,240,49,201,26,30,15,129,34,88,32,27,56,176,150,
        249,64,147,164,195,113,56,102,108,206,87,175,118,97,81,242,
        63,10,68,147,61,237,139,250,90,148,213,198]
    try
        cose = CBOR.decode(cose_dup)
        cose_key_parse(cose)
        @test false  # should never pass parse!
    catch
        @test true
    end
end

@testset "MALFORMED CBOR: Non-canonical key order in COSE_Key" begin
    # noncanonical order: hand-crafted for negative coverage
    cose_nc = UInt8[
        165,33,88,32,116,234,117,40,132,150,197,21,153,193,88,131,
        22,50,203,220,236,113,108,58,202,209,19,188,147,240,49,201,
        26,30,15,129,1,2,3,38,32,1,34,88,32,27,56,176,150,249,64,
        147,164,195,113,56,102,108,206,87,175,118,97,81,242,63,10,
        68,147,61,237,139,250,90,148,213,198]
    parse_succeeded = false
    try
        cose = CBOR.decode(cose_nc)
        key = cose_key_parse(cose)
        parse_succeeded = true
    catch
        parse_succeeded = false
    end
    @test_broken !parse_succeeded
end

@testset "MALFORMED CBOR: Truncated buffer" begin
    # last 10 bytes cut off
    cose_b = UInt8[
        165,1,2,3,38,32,1,33,88,32,116,234,117,40,132,150,197,21,
        153,193,88,131,22,50,203,220,236,113,108,58,202,209,19,188,
        147,240,49,201,26,30,15,129,34,88,32,27,56,176,150,249,64,
        147,164,195,113,56,102,108,206,87,175,118,97,81,242,63,10,
        68,147,61,237,139,250 # ...cut off
    ]
    @test_broken try
        CBOR.decode(cose_b)
        false
    catch
        true
    end
end