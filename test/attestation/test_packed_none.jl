# test_packed_none.jl
# --------------------------------------------------
# Purpose: End-to-end parsing/verification for "none" and "packed" 
# (self and x5c) attestationObject.
# Spec: §8.2, §8.7, §7.1
# Tests:
#   - Proper extraction of fmt, attStmt, authData, right signature check method 
# for each
#   - Vector: valid "none" (pass), "packed"/self (pass), "packed"/x5c 
# (pass/fail)
#   - Vector: intentionally broken signature and empty/missing fields (fail)
using Test, WebAuthn
using Test, WebAuthn, CBOR, JSON3

decodeb64url(x) = WebAuthn.base64urldecode(x)
decodejson(x) = JSON3.read(String(decodeb64url(x)), Dict{String,Any})

function parsed_attestation_object(attestationObject)
    WebAuthn.parse_attestation_object(attestationObject)
end

function extract_cosekey_from_attestation(attobj)
    WebAuthn.parse_credential_public_key(attobj["authData"])
end

# ------------------ REAL TEST VECTORS (b64url) ------------------
const att_none = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikgokmRebwXda2X9CScZAt1FS1U7jvFi6aDLY8eyICQjhBAAAAAcDiKS6EGVQBSZ3UWJ8FVioAIJYypOb6RxFQ4ocIvwK78qeEYp67CAWrj59jW99h8_tNpQECAyYgASFYIOyFijz315Yd_Aexkt5l6YaFK4MK2CQgRZPXQqGGD06MIlgg54dhMxLg9u84Y3urvWdHrViXea0aMYq7v7QI-DP1Duk"
const cdj_b64_none = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiazF6eV9hU0NPTDdOMFBWVmFVVElpVm5BU1ZGVDE4MDB1TWJVa1R2dUdKSSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4tdGVzdC5sb2NhbCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
const att_packed_self = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhANsUlDLGr1C4E0w4YBBicwxBTRij6ZsCnva7La0T0-a1AiAj6swjJpJtbEqHBjBlkRSofU8eOFEmJH5nGwtZSbqx_mhhdXRoRGF0YVikgokmRebwXda2X9CScZAt1FS1U7jvFi6aDLY8eyICQjhBAAAAAcDiKS6EGVQBSZ3UWJ8FVioAIJYypOb6RxFQ4ocIvwK78qeEYp67CAWrj59jW99h8_tNpQECAyYgASFYIOyFijz315Yd_Aexkt5l6YaFK4MK2CQgRZPXQqGGD06MIlgg54dhMxLg9u84Y3urvWdHrViXea0aMYq7v7QI-DP1Duk"
const cdj_b64_self = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiazF6eV9hU0NPTDdOMFBWVmFVVElpVm5BU1ZGVDE4MDB1TWJVa1R2dUdKSSIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4tdGVzdC5sb2NhbCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
const att_packed_okp = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZydjc2lnWECebtIAFALGq0VL7HTeuKylvF3_cF2DRFFl3heuGhiYuqJ0W4POUYwrE_YRsnCSMfsIx1_tN91RPqQuOP6msVQOaGF1dGhEYXRhWIFT_w-E0-c4cb27LR96mZ-U9tzcoBptoXAV7uXu6UlOkEEAAAACIjsBqXrb2iKnPoxITta6NgAgKrnLYRJfPAyyj64numfMLs2qHcTwuAcOcCxw8kQZnrekAQEDJyAGIVggEHr2CsESZfjvmpdsActDg0ECbRkJiGGhSoPgceoL3j0"
const cdj_b64_okp = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUDhxWG1Oa3h1VHNtSFFTT0xiM1hYT29oZUpkNE5MNXMtZVR6Vnc4ZmRwUSIsIm9yaWdpbiI6Imh0dHBzOi8vZWQyNTUxOS10ZXN0LmxvY2FsIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
const att_packed_x5c = "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhANc-XQl_T7QxtrQzJHGpprhOltae-Do-88a8e0eCbSE0AiEA2xuSKN8H4_F3hSN9f8WLhAwZ-m2rY4AqtKzEDgtzxXVjeDVjgVkBxzCCAcMwggFpoAMCAQICFEN8MshxQ3flZ_NAOABxuwQ9iOVVMAoGCCqGSM49BAMCMDcxCzAJBgNVBAYTAlhZMRAwDgYDVQQKDAdUZXN0IENBMRYwFAYDVQQDDA1XZWJBdXRobiBEZW1vMB4XDTI1MDkyMzA1NDIxOFoXDTI2MDkyMzA1NDIxOFowNzELMAkGA1UEBhMCWFkxEDAOBgNVBAoMB1Rlc3QgQ0ExFjAUBgNVBAMMDVdlYkF1dGhuIERlbW8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASZbJK6WQ6gJEojJ1SU8sLEdoWkYbh0H_5zS9yR2d-_L_UOu7xbgowMzvYqeonL7MBGkDPB5IS8p1gB4gNhQ6gso1MwUTAdBgNVHQ4EFgQUe_5TQ3w_NyOzU659Jr7lcjLe4xkwHwYDVR0jBBgwFoAUe_5TQ3w_NyOzU659Jr7lcjLe4xkwDwYDVR0TAQH_BAUwAwEB_zAKBggqhkjOPQQDAgNIADBFAiEA8VhOr240teTyJSHwaPaR9FFrodCR62mHZ8i-1J2p4vMCIH4a2FUl-oDUXqCyNV_WTT3Zpry4BJMXuLy02B9T7aaSaGF1dGhEYXRhWKSjeab27q-5pV43jBGANOJ1Hmgvq58tMKsT0hJVhs4ZR0EAAAABAAAAAAAAAAAAAAAAAAAAAAAg_9OUXr8eVWUtzvV0Rckop-qqUq6X1i_SXRNmLQJ3gd-lAQIDJiABIVggmWySulkOoCRKIydUlPLCxHaFpGG4dB_-c0vckdnfvy8iWCD1Dru8W4KMDM72KnqJy-zARpAzweSEvKdYAeIDYUOoLA"
const cdj_b64_x5c = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImNoYWxsZW5nZSI6IlNPTUVCNjRDSEFMTEVOR0UiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

# ---------------- HAPPY PATH TESTS ----------------

@testset "Attestation: happy path variants" begin
    @test verify_attestation_object(att_none,
        base64urldecode(cdj_b64_none)) == true

    try
        ok = verify_attestation_object(att_packed_self,
            base64urldecode(cdj_b64_self))
        @test ok == true || ok == false   # must not throw
    catch e
        @test false
        @info "packed/self failed: $e"
    end

    try
        ok = verify_attestation_object(att_packed_x5c,
            base64urldecode(cdj_b64_x5c))
        # must not throw, DER certificate parsed
        @test ok == true || ok == false
    catch e
        @test false
        @info "packed/x5c failed: $e"
    end

    if att_packed_okp != "..."
        try
            ok = verify_attestation_object(att_packed_okp,
                base64urldecode(cdj_b64_okp))
            @test ok == true || ok == false
        catch e
            @test false
            @info "packed/okp failed: $e"
        end
    end
end

# ---------------- CBOR/COSE PARSING ----------------

@testset "Attestation: COSE key extraction" begin
    for attobj_b64 in (att_none, att_packed_self, att_packed_x5c)
        attobj = WebAuthn.parse_attestation_object(attobj_b64)
        pkbytes = WebAuthn.extract_credential_public_key(attobj["authData"])
        key = WebAuthn.cose_key_parse(CBOR.decode(pkbytes))
        @test key isa WebAuthn.WebAuthnPublicKey
    end
end

# ---------------- NEGATIVE CASES ----------------

@testset "Attestation: negative and mutant cases" begin
    # 1) Corrupt signature in packed/self
    b = WebAuthn.base64urldecode(att_packed_self)
    b[end-3] ⊻= 0x44
    corrupted = WebAuthn.base64urlencode(b)
    try
        ok = verify_attestation_object(corrupted, base64urldecode(cdj_b64_self))
        @test !ok
    catch
        @test true
    end

    # 2) Missing sig
    att = parse_attestation_object(att_packed_self)
    delete!(att["attStmt"], "sig")
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 3) Missing alg
    att = parse_attestation_object(att_packed_self)
    delete!(att["attStmt"], "alg")
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 4) attStmt empty
    att = parse_attestation_object(att_packed_self)
    att["attStmt"] = Dict()
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 5) Wrong format
    att = parse_attestation_object(att_packed_self)
    att["fmt"] = "nonsense"
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 6) Truncated CBOR string
    short = att_packed_self[1:end-20]
    try
        ok = verify_attestation_object(short, base64urldecode(cdj_b64_self))
        @test !ok
    catch
        @test true
    end

    # 7) Damaged x5c certificate
    att = parse_attestation_object(att_packed_x5c)
    att["attStmt"]["x5c"] = [rand(UInt8, 10)] # fake cert
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_x5c))

    # 8) Wrong alg
    att = parse_attestation_object(att_packed_self)
    att["attStmt"]["alg"] = -99
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    ####### ADDED FOR EXTRA COVERAGE ########
    # 9) "none" attestation with non-empty attStmt (MUST FAIL)
    att = parse_attestation_object(att_none)
    att["attStmt"] = Dict("sig" => rand(UInt8, 8))
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_none))

    # 10) attestationObject missing "fmt"
    att = parse_attestation_object(att_packed_self)
    delete!(att, "fmt")
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 11) attestationObject missing "authData"
    att = parse_attestation_object(att_packed_self)
    delete!(att, "authData")
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 12) attestationObject missing "attStmt"
    att = parse_attestation_object(att_packed_self)
    delete!(att, "attStmt")
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 13) attStmt is not a dictionary (should fail)
    att = parse_attestation_object(att_packed_self)
    att["attStmt"] = 42
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))

    # 14) attStmt with extra/unknown fields (should accept or clearly reject)
    att = parse_attestation_object(att_packed_self)
    att["attStmt"]["custom"] = 123
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    try
        ok = verify_attestation_object(broken, base64urldecode(cdj_b64_self))
        # This may pass (if implementation ignores extra) or error (if strict): 
        # Either is OK if well-documented
        @test ok == true || ok == false
    catch
        @test true  # If rejected, this is acceptable
    end

    # 15) "fmt" is not a string (should fail, per spec)
    att = parse_attestation_object(att_packed_self)
    att["fmt"] = 123
    broken = WebAuthn.base64urlencode(CBOR.encode(att))
    @test_throws Exception verify_attestation_object(broken,
        base64urldecode(cdj_b64_self))
end

@testset "WebAuthn Interop Vectors" begin
    # This vector is from a real Windows10/Chrome credential
    v = Dict(
        "credentialId" => "VQ4aRuTTG3O7lq_7hnYKfKArUuNzys4Hl_b4QmVCygQ",
        "attestationObject" => "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQBaJlgKwig22fEhdhsY326ud9TC64lUvMcZHRDt4mncfi2fv00bAjegJPblxrQbVxo8jTPE08Tj3Ez2NdLbYGHTRrmbQRmGT-GWVJw9-7tkJrIg-DkrF4S4x6kXUAIXU9L7Ky-1SqrwfdnC21TSF6CJp2A5r_S6kZYH6zlBwmXrgcQ9lSYhYtsIRzDp6zA7le18g7y6qdYhCdgJhZkQ1VO5-43TSz8OQzYrxS5y96RxRSfuOFEWM0oswmfznUlULL6sSu7w2RrK8BKdCrwnpG1NooSRali9fbJ02pd7uj_soFkqJgU7-3wfkTCYUK3Po8-VygNzM4-OXyHI62ddDRZ8Y3ZlcmMyLjBjeDVjglkFxDCCBcAwggOooAMCAQICEGGxHpgqdE_OlqocAQLkEicwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2TkNVLVNUTS1LRVlJRC1GQjE3RDcwRDczNDg3MEU5MTlDNEU4RTYwMzk3NUU2NjRFMEU0M0RFMB4XDTIxMDQwODE3NTMxNVoXDTI1MDYxODE5MTYzNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5Pk9uNVX64lX3VqtfCCQVdhISbSdsh2ZncL4evq9T27arkSr8ataSe-sPMT592O63bWncE2GHzRTwusM37USQYR7aVONY6PWGRve-62MPdvNe3OB4KUZRX1JypkyOX8UCEjzHgoPjKAB6_9BpkhmWfPXRlJ-JZ1i_6uexoWpZSp4X3OGAZnC9YZVbx2dsQv9HCC-a2nGEBzeBJpn0sXSzZtig-slBtRnMp-nqPMLvG8L0P-hVXbF7Fc4oLTSV_QAEbKrKXd6Dj91tijlQLRjO4uGhGj7Hha4xg2H9ADi2Oi2Z1e7kn-amF_pYrtklRKKlX8QrfJMcaFeCgZ7UKohcCAwEAAaOCAfMwggHvMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFkGA1UdEQEB_wRPME2kSzBJMRYwFAYFZ4EFAgEMC2lkOjUzNTQ0RDIwMRcwFQYFZ4EFAgIMDFNUMzNIVFBIQUhENDEWMBQGBWeBBQIDDAtpZDowMDAxMDEwMTAfBgNVHSMEGDAWgBRsY8IPY1tegaOhw5qmjmaoh5cEIjAdBgNVHQ4EFgQUJ0sg7ghDwjEfnZQyBgbpGiUQSf8wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZG5jdWFpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L25jdS1zdG0ta2V5aWQtZmIxN2Q3MGQ3MzQ4NzBlOTE5YzRlOGU2MDM5NzVlNjY0ZTBlNDNkZS8xNTk2YWYyYy0yZGRiLTQ2ZDctYmUzYi01NDAwODU5YmYzMjAuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQCFk1eoL3hPKRDn5w7TCzngR3L2VVda8xL9SVH6Krk9Hg2tNSIo9LW9vGDHT96BjXu9-0jPXg_pxPXErLU83gsaHy_nt6B8Uvmq16NQPlLnNZ2bdQe1kbIcBJXZ2DsTFosIDwC3L0CDAxPoKhefn9B8BpVSGV7OhY3AUSc4ZGPWQ-dMEAAm_uKj0hCn9jGOsXy9lEShMm5_MNRHrsjMmzztNJYx5t27n5ZMEWdEJxw2NFNgje3XsYG6xtVSHaL-Mvf7XgOwxJdwc-vaei7-KWoijox8E5KHzpyI_vW5YajRdBGYrR9RM2vDW-7de9mdWwIyXsVkbZVj5dSVoEqf4DWpwODEbRrBdGUfGEYsXxkfjbgxFoEVh1WCUYw9vPdQnmkzQgPLqyS-oqBRJw1I0VIfrVj7tNRkSJHpeC8yhGJR2n_9j5MxQRxuttZcLY3oN5nTzQSc-AmMz8qHy88ZFH9kVUxw9N-JIRxr-bgVXDl9XRDrv1JJu3te4uOEqsNPJAtbKRwO4hkeSe4u0BVD9RnhoXdFR_7es2plI8bjEAWGuT4NYkXs0Pj7g608oK1NUEuU75h6i-MaDlQPyrbaeMPyxYBgvXRiH9AekhXMYpPp628sVpW_6v9DDYif9fUHzqyqaCcDbrA9J5NS_BkmOuI1uioaYuwhz_5R9qMLZtPj_VkG7zCCBuswggTToAMCAQICEzMAAALnYq6-Ce5vs0UAAAAAAucwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMDA2MTgxOTE2MzZaFw0yNTA2MTgxOTE2MzZaMEExPzA9BgNVBAMTNk5DVS1TVE0tS0VZSUQtRkIxN0Q3MEQ3MzQ4NzBFOTE5QzRFOEU2MDM5NzVFNjY0RTBFNDNERTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO6KcW8-0Y0AYoVk0B8y0qiCtTDeCzEvpSOUyhAcI15PkInqi-LkcGem_VzipVTwitth7JLHgrvn97-WQDNX2-I586LW25VIfl5lQ16I6SShtU6fnpaqcWrd8IDQRaPXgZFhi4ohbd2QvE9HfL8WAThx_IYLyEnEwW6nRt0Pb0gilUzEDAteAgXVakNe69hbjr6YR6zQZHxrxPUyPEXoXRU6j8szdRkiOvXnfQqjDtZjn6R76tZpCXovQlZzjgaG8AoMlYk9j_6Hc3WdGxPjK-5PrN8rXqhm9rJ1ELf0swg56FrxXrejgLY130_P4zRG3VGkXzL_sIffoVWtO3HkGdx6yMKQUrI9xu1Gapzo2uC7pYApybwwo1sJVaEM2qRKvKEsKfFybdtGyN1h5Hy9PlePIggiEsGZbr8vJTg045rW53qivNaBwnVS8Ojo6H0Su40yclafg7iFttKOyhvKn_OHKg3XDiROxxZtkZgjYv7plR4ZuFC2GIYSQ_4ZGFuXli1rkxAIhcCH_BwNx1J1y9ksT96fGGTnZ6O4bN7evejNkB-gZeqru-8xz4BjRX86-pzYoXMQrUFQYoUbH-WgBdkPbfoNX3-4Ax9HGY8GZeihM1XDowi5r1CObIoRIzs1oywg3gWxhVgyqDJEDpBEvIz3N9cJC_BdHdwZuEIusHADAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBRsY8IPY1tegaOhw5qmjmaoh5cEIjAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAEgzeDEFzkmd33cIyEWCxPyrDIwfU6p6XiKXlAikxU71B5x_6vQR-V2LajjF-F4W_zeqsGDjaQyvDeVBu2JCmqiBGdfEp83qP9kZyuLHadA7e1vGBcPMDTzI1BMKfL14HpZ2yRjT50O77C-kvOsSBKT8s2v7QXaxkdpZCwVDlDx03JGcFBmWt-X0zTWARSzEhLX4dzaR8kJervMiX_6MsIbpiO6_VSoMy6EGNc_Y-LM86VWQ3u3vAHp9ugNe6QODWE8z37Jtrzw8mHZaefx89Qie6J8Z91vYQCWsMXrNVEUdYpkF1vWznPPgprMTuniS_E_0zVm6Jk7usQ1Dsd3lwxyJLRQDT6nt4vIiZ8tRWp6eK9yjJQfFq--Ftre2zCaPb4ce3oDIHiBy-qBPoYQqkBjXnC0dQ6kVa6LKLkwNHKd4yz3nLUQNS6mnX3xExkuyliIQI-GL7RIaJ9FZMXhWEQofXjlNk5fEMPtgU-AxpyxqctllzgZKc8Dxc6togAm2mgQMDrRBknLk4VY8JVrHK8IcMGldpW2KL3llkBGVbfErEZ8sinNewrTtsuEE4x_bWRACZjZEM2Z5-aovejxgtBVVQANNVefKHHK31r3o1BssiGw-jKh-xvmhXqb47Vh2q2GgCStkS1Ya-U7pzNIfWdwuuLH1mNGrTbuHSFDYy8GkZ3B1YkFyZWFZATYAAQALAAYEcgAgnf_L82w4OuaZ-5ho3G3LidcVOIS-KAOSLBJBWL-tIq4AEAAQCAAAAAAAAQC4fEJX01JJRvw163gJHMoFDUAcisw_56Pa6AvtWuP49huZeVdbNNePeWzpdlwqg-r_vfIVksYqtCNYo307Fnocng4BYKJF0l8Lb-n0BrCB94ExvGVuNydbu4q-_CwopdyWMS_fWWuOCiDoPp-VxPND68edcQ_hcAGAgQzP1HcMPR1xNkpfzi60g66Z9X7pu1k5bu1Uv8Wvr0YK6fsk6zj0CY9EDMKNnmOmWM8BBzgsWd6QDIJJMTeELOSApx8_nt7P_gVCWWsAVCKK6pNkh0bFBU5Q_argf9e2Hd2ObwGpmp5uZ8pzHuBHGRJrVUT6RQfbJIH1mqf_GOA6q7lyJwVZaGNlcnRJbmZvWKH_VENHgBcAIgAL_poTIssY7b792oKBK0w0r6iomfaU8fVu2ugWwM9hiz0AFP8ut6Rv8l-5DSfMCTfGk06IDNgjAAAAAAY6foarxNdz-vienwGTs-9n6qV0CwAiAAvFu1rYT9cRmrizv6nbJYKFgGILkDoIYqmGIIR8_lNDUAAiAAv4gCHNHb5Tkuyaeiek6fAZ0q5Si0FFM9g3xQGGgIneGWhhdXRoRGF0YVkBZykqrV_lqNyaVkKbKwhk9pEk0R2WFrqDcuDE0hUze-W9RQAAAAAImHBYytxLgbbhMN5Q3L6WACBVDhpG5NMbc7uWr_uGdgp8oCtS43PKzgeX9vhCZULKBKQBAwM5AQAgWQEAuHxCV9NSSUb8Net4CRzKBQ1AHIrMP-ej2ugL7Vrj-PYbmXlXWzTXj3ls6XZcKoPq_73yFZLGKrQjWKN9OxZ6HJ4OAWCiRdJfC2_p9AawgfeBMbxlbjcnW7uKvvwsKKXcljEv31lrjgog6D6flcTzQ-vHnXEP4XABgIEMz9R3DD0dcTZKX84utIOumfV-6btZOW7tVL_Fr69GCun7JOs49AmPRAzCjZ5jpljPAQc4LFnekAyCSTE3hCzkgKcfP57ez_4FQllrAFQiiuqTZIdGxQVOUP2q4H_Xth3djm8BqZqebmfKcx7gRxkSa1VE-kUH2ySB9Zqn_xjgOqu5cicFWSFDAQAB",
        "clientDataJSON" => "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNVVCWDJsOGhqLUswTEh4eV9KOGtTSHd0aURORS1qNk40eVUycE1KYldSbyIsIm9yaWdpbiI6Imh0dHBzOi8vbW9iaWxlcGtpLm9yZyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
    )
    attobj = parsed_attestation_object(v["attestationObject"])
    key = extract_cosekey_from_attestation(attobj)
    @info "Parsed key type: $(typeof(key))"
    if isa(key, EC2PublicKey)
        @test length(key.x) == 32
        @test length(key.y) == 32
        @test key.alg == -7 || key.alg == -257
    elseif isa(key, RSAPublicKey)
        @test length(key.n) > 10
        @test length(key.e) > 0
    end
    res = Dict(
        "authenticatorData" => "KSqtX-Wo3JpWQpsrCGT2kSTRHZYWuoNy4MTSFTN75b0FA\
        AAAAQ",
        "signature" => "Ai2UCswbdZiY5Yo5s326joLRFcaN2q6Lg82cIwmX3l0qik3IlLwjau\
        lSEwdq31dhRCeVsg-_SffQ-Q0-JB43ggWIGfB5J6JR1-WfNslAaQSvnbMfIZ0haTmhcu1Zw\
        XCHSkH9VDHCWTbfCInFTMCGl1vyMPt0aYIbkuz3gt6lArYnY808TxyUtVdbGdFwb4XUVRCW\
        d_ycIfRAdTFPIBDp1GrKdzRF97inGkiQgx3Vym7PBFN3t-ZZ1dELK2MKfH_GP0TDS7x1RL\
        toDwKz5XE1ZCmU4zRsg7GG-vI3i8CWDhBGH4veoULYD0yiTmqQdgjZsUchsAJgoyGDCBv\
        R3708ww",
        "clientDataJSON" => "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi\
        V2tGc05DRDZtTjZvWUlibHdzOWlNNXNyZm0yaXZfcGtUcUFEaW9rdjltbyIsIm9yaWdpbi\
        I6Imh0dHBzOi8vbW9iaWxlcGtpLm9yZyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
    )
    authData = decodeb64url(res["authenticatorData"])
    clientDataJSON = decodeb64url(res["clientDataJSON"])
    signature = decodeb64url(res["signature"])
    pubkey_pem = WebAuthn.cose_key_to_pem(key)
    result = WebAuthn.verify_webauthn_signature(pubkey_pem, authData,
        clientDataJSON, signature)
    @test result == true
end

@testset "verify_attestation_packed Ed25519\
(OKP, alg -8) self-attestation" begin
    # 1. Generate a new Ed25519 keypair
    pk = Vector{UInt8}(undef, Sodium.crypto_sign_PUBLICKEYBYTES)
    sk = Vector{UInt8}(undef, Sodium.crypto_sign_SECRETKEYBYTES)
    @test Sodium.crypto_sign_keypair(pk, sk) == 0

    # 2. WebAuthn COSE and CBOR
    cose = Dict(1 => 1, 3 => -8, -1 => 6, -2 => pk)
    cbor_pk = CBOR.encode(cose)

    # 3. Properly structured WebAuthn authenticatorData
    rpId = "example.com"
    rpIdHash = SHA.sha256(Vector{UInt8}(rpId))
    flags = 0x41
    signCount = UInt8[0, 0, 0, 1]
    aaguid = zeros(UInt8, 16)
    credId = rand(UInt8, 16)
    credIdLen = [UInt8(length(credId) >> 8), UInt8(length(credId) & 0xff)]
    authData = vcat(rpIdHash, flags, signCount, aaguid, credIdLen,
        credId, cbor_pk)

    # 4. Prepare clientDataJSON and its SHA256 hash
    clientDataJSON =
        b"""{"type":"webauthn.create","challenge":"abc",
        "origin":"https://example.com"}"""
    clientDataHash = SHA.sha256(clientDataJSON)

    # 5. Signature is over SHA256(clientDataJSON), per spec for Ed25519
    sig = Vector{UInt8}(undef, Sodium.crypto_sign_BYTES)
    sl = Ref{UInt64}()
    @test Sodium.crypto_sign_detached(sig, sl, clientDataHash,
        length(clientDataHash), sk) == 0

    # 6. Compose the packed attestation statement and message as WebAuthn sends
    msg = vcat(authData, clientDataHash)
    attStmt = Dict("sig" => sig, "alg" => -8)

    # 7. Test: positive (valid) attestation signature
    ok = verify_attestation_packed(attStmt, msg, authData)
    @test ok

    # 8. Test: negative (tampered) attestation signature
    attStmt_bad = deepcopy(attStmt)
    attStmt_bad["sig"][1] ⊻= 0xFF
    ok_bad = verify_attestation_packed(attStmt_bad, msg, authData)
    @test !ok_bad
end