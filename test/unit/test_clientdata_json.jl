using Test, WebAuthn, JSON3

@testset "clientDataJSON Parse/Checks" begin
    # Required fields, correct input
    challenge = generate_challenge(16)
    good_dict = Dict(
        "type" => "webauthn.create",
        "challenge" => challenge,
        "origin" => "https://webauthn.test",
        "crossOrigin" => false
    )
    cdj_json = JSON3.write(good_dict)
    b64 = base64urlencode(Vector{UInt8}(cdj_json))
    parsed = parse_clientdata_json(b64)
    @test parsed["type"] == "webauthn.create"
    @test parsed["challenge"] == challenge
    @test parsed["origin"] == "https://webauthn.test"
    @test haskey(parsed, "crossOrigin")
    @test parsed["crossOrigin"] === false

    # Optional tokenBinding field
    dict_tb = merge(good_dict, Dict(
        "tokenBinding" => Dict("status" => "supported")))
    b64tb = base64urlencode(Vector{UInt8}(JSON3.write(dict_tb)))
    parsed_tb = parse_clientdata_json(b64tb)
    @test haskey(parsed_tb, "tokenBinding")
    @test parsed_tb["tokenBinding"]["status"] == "supported"

    # Accept missing crossOrigin (still legal)
    short_dict = Dict(
        "type" => "webauthn.get",
        "challenge" => challenge,
        "origin" => "https://demo"
    )
    parsed_short = parse_clientdata_json(
        base64urlencode(Vector{UInt8}(JSON3.write(short_dict))))
    @test parsed_short["type"] == "webauthn.get"
    @test parsed_short["origin"] == "https://demo"
    @test !haskey(parsed_short, "crossOrigin")

    # Malformed base64 input
    @test_throws ArgumentError parse_clientdata_json("!!!!!!!")
    @test_throws ArgumentError parse_clientdata_json("%&)*)%&")

    # Not JSON after decode (e.g. random bytes, or NUL in UTF8)
    bad_bin = base64urlencode(Vector{UInt8}([0xde, 0xad, 0xbe, 0xef]))
    @test_throws Exception parse_clientdata_json(bad_bin)
    not_json = base64urlencode(Vector{UInt8}("definitely not json" * '\0'))
    @test_throws Exception parse_clientdata_json(not_json)

    # Missing required fields: type, origin, challenge
    minimal = Dict("foo" => 123)
    b64min = base64urlencode(Vector{UInt8}(JSON3.write(minimal)))
    parsed_min = parse_clientdata_json(b64min)
    @test !haskey(parsed_min, "type")
    @test !haskey(parsed_min, "origin")
    @test !haskey(parsed_min, "challenge")

    # Wrong type string accepted, app code must check logic
    wrong_type = merge(good_dict, Dict("type" => "webauthn!create"))
    b64wrong = base64urlencode(Vector{UInt8}(JSON3.write(wrong_type)))
    parsed_wrong = parse_clientdata_json(b64wrong)
    @test parsed_wrong["type"] == "webauthn!create"

    # Challenge mismatch (handled later by logic, not here)
    other_chal = generate_challenge(16)
    ref_chal = challenge
    dict_mismatch = merge(good_dict, Dict("challenge" => other_chal))
    b64mm = base64urlencode(Vector{UInt8}(JSON3.write(dict_mismatch)))
    parsed_mismatch = parse_clientdata_json(b64mm)
    @test parsed_mismatch["challenge"] != ref_chal

    # Trailing whitespace/newlines in JSON (legal)
    json_ws = JSON3.write(good_dict) * "\n"
    b64ws = base64urlencode(Vector{UInt8}(json_ws))
    parsed_ws = parse_clientdata_json(b64ws)
    @test parsed_ws["challenge"] == challenge

    # Long challenge (spec allows up to 255 chars)
    long_chal = base64urlencode(rand(UInt8, 64))
    long_dict = merge(good_dict, Dict("challenge" => long_chal))
    long_b64 = base64urlencode(Vector{UInt8}(JSON3.write(long_dict)))
    parsed_long = parse_clientdata_json(long_b64)
    @test parsed_long["challenge"] == long_chal

    # "type" field as non-string (should accept as JSON, fail by app code)
    notstr_dict = merge(good_dict, Dict("type" => 1234))
    b64notstr = base64urlencode(Vector{UInt8}(JSON3.write(notstr_dict)))
    parsed_notstr = parse_clientdata_json(b64notstr)
    @test parsed_notstr["type"] == 1234

    # Edge: empty JSON object
    edict = base64urlencode(Vector{UInt8}("{}"))
    edgedec = parse_clientdata_json(edict)
    @test length(edgedec) == 0

    # Accept extra/unknown fields (extension-ready)
    extra_dict = merge(good_dict, Dict("extraField" => [1, 2, 3]))
    b64extra = base64urlencode(Vector{UInt8}(JSON3.write(extra_dict)))
    parsed_extra = parse_clientdata_json(b64extra)
    @test parsed_extra["extraField"] == [1, 2, 3]

    # Unicode allowed in origin and type (should decode cleanly)
    unicode_dict = merge(good_dict, Dict(
        "origin" => "https://täst.example.com",
        "type" => "wébauthn.create"))
    b64unicode = base64urlencode(Vector{UInt8}(JSON3.write(unicode_dict)))
    parsed_unicode = parse_clientdata_json(b64unicode)
    @test parsed_unicode["origin"] == "https://täst.example.com"
    @test parsed_unicode["type"] == "wébauthn.create"
end

@testset "clientDataJSON: none-ES256" begin
    cdj_bin = load_vector("vectors_ec2_none", "registration", 
    "clientDataJSON.bin")
    cdj = JSON3.read(String(cdj_bin))
    @test haskey(cdj, "challenge")
    @test haskey(cdj, "type")
    @test haskey(cdj, "origin")
    # Challenge is b64url and decodable, 32 bytes as in testvector
    chal = cdj["challenge"]
    d = base64urldecode(chal)
    @test length(d) == 32
end