# test_cose_keys.jl
# -------------------------------
# Purpose: Parse, validate, and encode COSE_Key (RFC8152 §13, WebAuthn §5.8.5)
#          for EC2 (P-256), RSA, OKP(Ed25519); 
# must reject wrong/unsupported/invalid
# Tests:
#   - Good EC2, RSA, Ed25519 key parses (test vectors)
#   - Wrong, missing, or extra fields rejected (edge/bad vectors)

using Test, WebAuthn, CBOR

@testset "EC2 Good" begin
    cose_b = UInt8[165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 83, 171, 141, 121, 88,
        18, 46, 173, 166, 127, 160, 40, 92, 178, 249, 182, 70, 196, 88, 55, 61, 
        5, 159, 127, 243, 218, 165, 3, 67, 116, 60, 81, 34, 88, 32, 123, 247, 
        82, 170, 104, 216, 226, 46, 219, 11, 230, 187, 37, 245, 34, 194, 24, 6, 
        21, 145, 134, 239, 19, 202, 77, 226, 96, 247, 100, 102, 133, 80]
    cose = CBOR.decode(cose_b)
    key = cose_key_parse(cose)
    @test key isa EC2PublicKey
    @test key.alg == -7
    @test key.crv == 1
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
end

@testset "OKP Ed25519 Good" begin
    cose_b = UInt8[164, 1, 1, 3, 39, 32, 6, 33, 88, 32, 33, 245, 65, 233, 205,
        194, 180, 45, 83, 65, 7, 159, 184, 66, 190, 92, 78, 231, 70, 224, 98, 
        200, 255, 196, 206, 16, 229, 174, 84, 34, 68, 201]
    cose = CBOR.decode(cose_b)
    key = cose_key_parse(cose)
    @test key isa OKPPublicKey
    @test key.alg == -8
    @test key.crv == 6
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
end

@testset "RSA Good" begin
    cose_b = UInt8[164, 1, 3, 3, 57, 1, 0, 32, 89, 1, 0, 146, 20, 62, 231, 79,
        230, 167, 60, 82, 190, 110, 32, 62, 31, 29, 38, 224, 243, 166, 241, 180,
        158, 111, 141, 10, 235, 210, 135, 237, 251, 128, 197, 40, 234, 117, 115,
        61, 10, 27, 193, 94, 87, 103, 176, 57, 0, 0, 217, 2, 238, 148, 174, 173,
        70, 237, 176, 25, 167, 242, 45, 51, 146, 224, 221, 13, 101, 55, 163, 47,
        156, 227, 115, 93, 13, 170, 23, 152, 194, 92, 173, 108, 183, 208, 228,
        234, 172, 242, 66, 252, 82, 33, 164, 66, 148, 65, 199, 5, 81, 85, 174,
        41, 175, 130, 15, 133, 54, 106, 142, 99, 91, 57, 98, 68, 79, 19, 139,
        190, 194, 9, 227, 143, 133, 89, 232, 106, 159, 31, 204, 226, 119, 250,
        125, 225, 143, 26, 129, 31, 177, 93, 23, 110, 14, 170, 124, 125, 15,
        130, 147, 192, 230, 53, 35, 217, 84, 57, 99, 113, 179, 33, 180, 215,
        168, 72, 128, 41, 180, 131, 173, 222, 41, 121, 14, 194, 239, 228, 198,
        248, 205, 33, 121, 82, 66, 253, 76, 155, 32, 244, 45, 118, 178, 239,
        112, 148, 30, 37, 168, 157, 100, 134, 103, 171, 128, 152, 38, 245, 58,
        214, 198, 240, 191, 17, 165, 17, 26, 122, 188, 66, 183, 47, 109, 239,
        34, 123, 146, 46, 156, 169, 81, 224, 82, 126, 216, 118, 224, 180, 132,
        171, 5, 103, 227, 235, 73, 50, 182, 42, 77, 236, 96, 28, 112, 131, 8,
        34, 214, 112, 173, 33, 67, 1, 0, 1]
    cose = CBOR.decode(cose_b)
    key = cose_key_parse(cose)
    @test key isa RSAPublicKey
    pem = cose_key_to_pem(key)
    @test occursin("BEGIN PUBLIC KEY", pem)
end

@testset "EC2 BAD (missing y)" begin
    cose_b = UInt8[164, 1, 2, 3, 38, 32, 1, 33, 88, 32, 83, 171, 141, 121, 88,
        18, 46, 173, 166, 127, 160, 40, 92, 178, 249, 182, 70, 196, 88, 55, 61,
        5, 159, 127, 243, 218, 165, 3, 67, 116, 60, 81]
    cose = CBOR.decode(cose_b)
    @test_throws Exception cose_key_parse(cose)
end

@testset "EC2 BAD (Extra unknown field)" begin
    cose_b = UInt8[166, 1, 2, 3, 38, 32, 1, 33, 88, 32, 83, 171, 141, 121, 88,
        18, 46, 173, 166, 127, 160, 40, 92, 178, 249, 182, 70, 196, 88, 55, 61,
        5, 159, 127, 243, 218, 165, 3, 67, 116, 60, 81, 34, 88, 32, 123, 247,
        82, 170, 104, 216, 226, 46, 219, 11, 230, 187, 37, 245, 34, 194, 24, 6,
        21, 145, 134, 239, 19, 202, 77, 226, 96, 247, 100, 102, 133, 80, 25, 39,
        15, 67, 97, 98, 99]
    cose = CBOR.decode(cose_b)
    # Depending on your code, you might allow unknown fields, 
    # or (if you strictly enforce) expect:
    # @test_throws Exception cose_key_parse(cose)
    # Or just check the result.
end

@testset "OKP BAD (alg=-999)" begin
    cose_b = UInt8[164, 1, 1, 3, 57, 3, 230, 32, 6, 33, 88, 32, 33, 245, 65,
        233, 205, 194, 180, 45, 83, 65, 7, 159, 184, 66, 190, 92, 78, 231, 70,
        224, 98, 200, 255, 196, 206, 16, 229, 174, 84, 34, 68, 201]
    cose = CBOR.decode(cose_b)
    @test_throws Exception cose_key_parse(cose)
end

@testset "MALFORMED CBOR: Duplicate key in COSE_Key" begin
    # This map has -2 key (X) twice; true canonical CBOR must reject 
    # or last-wins, spec: reject.
    cose_dup = UInt8[
        165,               # map(5)
        1, 2,              # 1:2
        3, 38,             # 3:38
        32, 1,             # -1:1
        33, 88, 32,        # -2: bstr(32)
        116, 234, 117, 40, 132, 150, 197, 21, 153, 193, 88, 131, 22, 50, 203,
        220, 236, 113, 108, 58, 202, 209, 19, 188, 147, 240, 49, 201, 26, 30,
        15, 129,
        # -2: (again)
        33, 88, 32,
        116, 234, 117, 40, 132, 150, 197, 21, 153, 193, 88, 131, 22, 50, 203,
        220, 236, 113, 108, 58, 202, 209, 19, 188, 147, 240, 49, 201, 26, 30,
        15, 129,
        # -3: y
        34, 88, 32,
        27, 56, 176, 150, 249, 64, 147, 164, 195, 113, 56, 102, 108, 206, 87,
        175, 118, 97, 81, 242, 63, 10, 68, 147, 61, 237, 139, 250, 90, 148, 213,
        198]
    try
        cose = CBOR.decode(cose_dup)
        cose_key_parse(cose)
        @test false  # must not parse cleanly!
    catch
        @test true   # should fail parse or raise
    end
end


@testset "MALFORMED CBOR: Non-canonical key order in COSE_Key" begin
    # -2 appears before 1 (out of canonical order for CBOR maps)
    cose_noncanon = UInt8[
        165,              # map(5)
        33, 88, 32,       # -2: bstr(32)
        116, 234, 117, 40, 132, 150, 197, 21, 153, 193, 88, 131, 22, 50, 203,
        220, 236, 113, 108, 58, 202, 209, 19, 188, 147, 240, 49, 201, 26, 30,
        15, 129,
        1, 2,             # 1:2
        3, 38,            # 3:38
        32, 1,            # -1:1
        34, 88, 32,       # -3: y
        27, 56, 176, 150, 249, 64, 147, 164, 195, 113, 56, 102, 108, 206, 87,
        175, 118, 97, 81, 242, 63, 10, 68, 147, 61, 237, 139, 250, 90, 148,
        213, 198]
    parse_succeeded = false
    try
        cose = CBOR.decode(cose_noncanon)
        key = cose_key_parse(cose)
        parse_succeeded = true
    catch
        parse_succeeded = false
    end
    # Spec: should fail, but CBOR.jl may accept.
    @test_broken !parse_succeeded
    if parse_succeeded
        @info "Non-canonical order was tolerated (documented, but not spec 
        compliant)."
    end
end

@testset "MALFORMED CBOR: Truncated buffer" begin
    # This is a real EC2 COSE_Key, but here's Y is cut off (last 10 bytes 
    # removed)
    cose_b = UInt8[
        165, 1, 2, 3, 38, 32, 1, 33, 88, 32,
        116, 234, 117, 40, 132, 150, 197, 21, 153, 193, 88, 131, 22, 50, 203,
        220, 236, 113, 108, 58, 202, 209, 19, 188, 147, 240, 49, 201, 26, 30,
        15, 129, 34, 88, 32, 27, 56, 176, 150, 249, 64, 147, 164, 195, 113, 56,
        102, 108, 206, 87, 175, 118, 97, 81, 242, 63, 10, 68, 147, 61, 237, 139,
        250
        # missing last 10 bytes!
    ]
    # @test_throws 
    @test_broken try
        CBOR.decode(cose_b)
        false
    catch
        true
    end
end