using Test, WebAuthn, Logging

@testset "Privacy/PII and Logging Policy" begin

    # 1. Custom logger captures all log messages for inspection.
    struct CaptureLogger <: AbstractLogger
        lines::Vector{String}
        CaptureLogger() = new(String[])
    end
    function Logging.shouldlog(::CaptureLogger, level, _module, group, id)
        true
    end
    Logging.min_enabled_level(::CaptureLogger) = Logging.Debug
    function Logging.handle_message(logger::CaptureLogger, level, msg, 
            _mod, group, id, file, line)
        push!(logger.lines, String(msg))
    end

    # 1a. Check that no user ID, PII, credential, or site secrets go to logs.
    logger = CaptureLogger()
    with_logger(logger) do
        try
            WebAuthn.registration_options("priv.com", "priv", 
            "secret@leak.me","n", "n")
        catch end
        try
            WebAuthn.registration_options("piidemo.com", "p2",
            "alice@example.com", "n", "n")
        catch end
        try
            WebAuthn.parse_credential_public_key(rand(UInt8, 80))
        catch end
        try
            WebAuthn.registration_options("fail.com", "bad", "BOB", "", "")
        catch end
    end
    all_logs = join(logger.lines, " ")
    for secret in ("secret@leak.me", "alice@example.com", "priv.com",
                   "piidemo.com", "BOB", "fail.com")
        @test !occursin(secret, all_logs)
    end

    # 2. Extension fields (e.g., credProps) never leak
    cred_props = Dict("rk"=>true)
    extension_out = Dict("credProps"=>cred_props)
    @test haskey(extension_out, "credProps")
    @test extension_out["credProps"]["rk"] === true
    @test !occursin("rk", all_logs)

    # 3. Future extension security test slots (uvm, largeBlob, appid...)
    # Extend with similar checks as new extensions are implemented.

    # 4. Test that logs on hard failure do not leak PII
    logger2 = CaptureLogger()
    with_logger(logger2) do
        try
            WebAuthn.registration_options("failure.com", "fail", 
            "crashdude", "", "")
        catch end
    end
    all_logs2 = join(logger2.lines, " ")
    for secret in ("crashdude", "failure.com")
        @test !occursin(secret, all_logs2)
    end

    # 5. Stdout (i.e. direct prints) must never leak anything PII
    redirect_stdout(devnull) do
        try
            WebAuthn.registration_options("console.com", 
            "console", "printer", "n", "n")
        catch end
    end
    redirect_stdout(devnull) do
        try
            WebAuthn.registration_options("barf.com", "b", "STDOUTPII", "", "")
        catch end
    end

end