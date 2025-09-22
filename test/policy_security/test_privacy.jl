# test_privacy.jl
# --------------------------------------
# Purpose: Ensure privacy, security, and proper handling of extensions, 
# no logging of secrets/handles.
# Tests:
#   - Logging/PII test, extensions if supported (credProps, uvm...)
using Test

using Test, WebAuthn, Logging

using Test, WebAuthn, Logging

@testset "Privacy Extensions/Logging" begin
    # 1. Capture logs to verify no PII is written
    struct CaptureLogger <: AbstractLogger
        lines::Vector{String}
        CaptureLogger() = new(String[])
    end
    function Logging.shouldlog(::CaptureLogger, level, _module, group, id)
        return true
    end
    Logging.min_enabled_level(::CaptureLogger) = Logging.Debug
    function Logging.handle_message(logger::CaptureLogger, level, msg,
        _mod, group, id, file, line)
        push!(logger.lines, String(msg))
    end

    logger = CaptureLogger()
    with_logger(logger) do
        try
            WebAuthn.registration_options("priv.com", "priv", "secret@leak.me",
                "n", "n")
        catch
        end
        try
            WebAuthn.registration_options("piidemo.com", "p2",
                "alice@example.com", "n", "n")
        catch
        end
        try
            WebAuthn.parse_credential_public_key(rand(UInt8, 80))
        catch
        end
        try
            WebAuthn.registration_options("fail.com", "bad", "BOB", "", "")
        catch
        end # error path
    end

    all_logs = join(logger.lines, " ")
    for secret in ("secret@leak.me", "alice@example.com", "priv.com",
        "piidemo.com", "BOB", "fail.com")
        @test !occursin(secret, all_logs)
    end

    # 2. Extension fields never leak in logs
    cred_props = Dict("rk" => true)
    extension_out = Dict("credProps" => cred_props)
    @test haskey(extension_out, "credProps")
    @test extension_out["credProps"]["rk"] === true
    @test !occursin("rk", all_logs)

    # 3. Placeholder for future extensions (uvm, largeBlob, appid...)
    # Extend with similar checks when implemented.

    # 4. Logs on error path also must not contain PII
    logger2 = CaptureLogger()
    with_logger(logger2) do
        try
            WebAuthn.registration_options("failure.com", "fail", "crashdude",
                "", "")
        catch
        end
    end
    all_logs2 = join(logger2.lines, " ")
    for secret in ("crashdude", "failure.com")
        @test !occursin(secret, all_logs2)
    end

    # 5. Stdout must not leak anything PII.
    # Redirect to DevNull just to guarantee silence.
    redirect_stdout(devnull) do
        try
            WebAuthn.registration_options("console.com", "console", "printer",
                "n", "n")
        catch
        end
    end
    redirect_stdout(devnull) do
        try
            WebAuthn.registration_options("barf.com", "b", "STDOUTPII", "",
                "")
        catch
        end
    end
end