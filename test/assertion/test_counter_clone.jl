using Test, WebAuthn

function signcount_is_valid(old::Integer, new::Integer)
    if old == 0
        return new >= 0
    elseif new == 0
        return true # non-incrementing: must tolerate reset/never increases
    elseif new > old
        return true
    else
        return false # CLONE/replay/duplicate
    end
end

@testset "signCount/Clone Detector" begin
    # First-time registration: any count (even zero) legal
    @test signcount_is_valid(0, 0)
    @test signcount_is_valid(0, 1)
    @test signcount_is_valid(0, 50000)

    # Typical monotonic increase, MUST succeed
    @test signcount_is_valid(5, 6)
    @test signcount_is_valid(10, 11)
    @test signcount_is_valid(50, 100)
    @test signcount_is_valid(1234, 7890)

    # CLONE/replay: value drops or repeats when old != 0 
    # (spec: forbidden, fail detection)
    @test !signcount_is_valid(10, 9)
    @test !signcount_is_valid(51, 20)
    @test !signcount_is_valid(3, 3)    # no change, not zero: forbidden
    @test !signcount_is_valid(99, 98)
    @test !signcount_is_valid(1, 1)

    # Allow "stuck" authenticator (non-incrementing: stays at 0 even after use)
    @test signcount_is_valid(25, 0)
    @test signcount_is_valid(40000, 0)

    # Negative count is always forbidden when old != 0
    @test !signcount_is_valid(10, -1)

    # Large jump (forward) MUST be legal
    @test signcount_is_valid(10, 99)
    @test signcount_is_valid(1, 1000000)

    # Old=0 and new negative: forbidden
    @test !signcount_is_valid(0, -1)
end