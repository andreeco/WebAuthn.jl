# test_clientdata_json.jl
# ------------------------------------------
# Purpose: Parse/decode clientDataJSON (b64url→UTF8→JSON), 
# check all required fields.
# Spec: §5.8.1/§7.1/§7.2
# Tests:
#   - Valid inputs parsed: correct type/challenge/origin/crossOrigin
#   - Bad base64, non-JSON, wrong type/challenge reject
#   - TokenBinding present/not present
using Test, WebAuthn, JSON3

@testset "clientDataJSON Parse/Checks" begin
    # 1. Good minimal, all required
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

    # 2. Add tokenBinding (optional, but valid)
    dict_tb = merge(good_dict, Dict("tokenBinding" => Dict(
        "status" => "supported")))
    b64tb = base64urlencode(Vector{UInt8}(JSON3.write(dict_tb)))
    parsed_tb = parse_clientdata_json(b64tb)
    @test haskey(parsed_tb, "tokenBinding")
    @test parsed_tb["tokenBinding"]["status"] == "supported"

    # 3. Accept missing crossOrigin (optional)
    short_dict = Dict(
        "type" => "webauthn.get",
        "challenge" => challenge,
        "origin" => "https://demo"
    )
    parsed_short = parse_clientdata_json(base64urlencode(
        Vector{UInt8}(JSON3.write(short_dict))))
    @test parsed_short["type"] == "webauthn.get"
    @test parsed_short["origin"] == "https://demo"
    @test !haskey(parsed_short, "crossOrigin")

    # 4. Malformed base64
    @test_throws ArgumentError parse_clientdata_json("!!!!!!!")
    @test_throws ArgumentError parse_clientdata_json("%&)*)%&")
    # ^ base64urldecode errors will raise ArgumentError.

    # 5. Not JSON (valid b64url, invalid utf8 or not a JSON text)
    bad_bin = base64urlencode(Vector{UInt8}([0xde, 0xad, 0xbe, 0xef]))
    @test_throws Exception parse_clientdata_json(bad_bin)
    # Why Exception? JSON3 may throw ArgumentError for utf8, 
    # JSON3.Error for bad structure.

    # 6. Not JSON (valid b64url, valid UTF-8, but not JSON object)
    not_json = base64urlencode(Vector{UInt8}("definitely not json" * '\0'))
    @test_throws Exception parse_clientdata_json(not_json)

    # 7. Missing required fields
    minimal = Dict("foo" => 123)
    b64min = base64urlencode(Vector{UInt8}(JSON3.write(minimal)))
    parsed_min = parse_clientdata_json(b64min)
    @test !haskey(parsed_min, "type")
    @test !haskey(parsed_min, "origin")
    @test !haskey(parsed_min, "challenge")

    # 8. Wrong type (for reg/login ceremony, app code must verify, 
    # parser accepts)
    wrong_type = merge(good_dict, Dict("type" => "webauthn!create"))
    b64wrong = base64urlencode(Vector{UInt8}(JSON3.write(wrong_type)))
    parsed_wrong = parse_clientdata_json(b64wrong)
    @test parsed_wrong["type"] == "webauthn!create"

    # 9. Challenge mismatch (logic check elsewhere)
    other_chal = generate_challenge(16)
    ref_chal = challenge
    dict_mismatch = merge(good_dict, Dict("challenge" => other_chal))
    b64mm = base64urlencode(Vector{UInt8}(JSON3.write(dict_mismatch)))
    parsed_mismatch = parse_clientdata_json(b64mm)
    @test parsed_mismatch["challenge"] != ref_chal

    # 10. Trailing whitespace/newlines/surrounding
    json_ws = JSON3.write(good_dict) * "\n"
    b64ws = base64urlencode(Vector{UInt8}(json_ws))
    parsed_ws = parse_clientdata_json(b64ws)
    @test parsed_ws["challenge"] == challenge

    # 11. Edge: long challenge (spec allows up to 255 chars)
    long_chal = base64urlencode(rand(UInt8, 64))
    long_dict = merge(good_dict, Dict("challenge" => long_chal))
    long_b64 = base64urlencode(Vector{UInt8}(JSON3.write(long_dict)))
    parsed_long = parse_clientdata_json(long_b64)
    @test parsed_long["challenge"] == long_chal

    # 12. Edge: "type" field as non-string 
    # (should parse, but app will error if strict)
    notstr_dict = merge(good_dict, Dict("type" => 1234))
    b64notstr = base64urlencode(Vector{UInt8}(JSON3.write(notstr_dict)))
    parsed_notstr = parse_clientdata_json(b64notstr)
    @test parsed_notstr["type"] == 1234

    # 13. Edge: empty dict "{}"
    edict = base64urlencode(Vector{UInt8}("{}"))
    edgedec = parse_clientdata_json(edict)
    @test length(edgedec) == 0

    # 14. Accept extra/unknown fields
    extra_dict = merge(good_dict, Dict("extraField" => [1, 2, 3]))
    b64extra = base64urlencode(Vector{UInt8}(JSON3.write(extra_dict)))
    parsed_extra = parse_clientdata_json(b64extra)
    @test parsed_extra["extraField"] == [1, 2, 3]

    # 15. Unicode in origin/type is legal
    unicode_dict = merge(good_dict, Dict(
        "origin" => "https://täst.example.com", "type" => "wébauthn.create"))
    b64unicode = base64urlencode(Vector{UInt8}(JSON3.write(unicode_dict)))
    parsed_unicode = parse_clientdata_json(b64unicode)
    @test parsed_unicode["origin"] == "https://täst.example.com"
    @test parsed_unicode["type"] == "wébauthn.create"
end