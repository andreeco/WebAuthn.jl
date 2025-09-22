# test_counter_clone.jl
# ---------------------------------------------
# Purpose: Checks signCount (anti-clone): new counter must strictly increase 
# except zero.
# Spec: §6.1.1, §7.2
# Tests:
#   - Pass: monotonically increasing counter  
#   - Warn/fail: signCount regression or replay  
using Test, WebAuthn

using Test

"WebAuthn signCount validation per spec: old=stored on server, 
new=from assertion"
function signcount_is_valid(old::Integer, new::Integer)
    # As per §6.1.1, §7.2:
    #   - If old == 0, any new >=0 accepted 
    # (authenticators that never increment)
    #   - If new > old, accept, update
    #   - If new == old, accept only if == 0 (non-incrementing authenticator)
    #   - If new < old and not zero: REPLAY CLONE ATTACK
    old == 0 ? true : ((new == 0) ? true : (new > old))
end

@testset "signCount/Clone Detector" begin
    # First-time use (zero counter is always okay)
    @test signcount_is_valid(0, 0)
    @test signcount_is_valid(0, 1)
    @test signcount_is_valid(0, 50000)
    # Normal increasing
    @test signcount_is_valid(1, 2)
    @test signcount_is_valid(50, 51)
    # Large jump
    @test signcount_is_valid(900, 1002)

    # Counter wrap/replay—MUST warn/fail per spec
    # Regression: CLONE
    @test !signcount_is_valid(10, 5)
    # Non-zero, not increasing: CLONE/REPLAY
    @test !signcount_is_valid(10, 10)
    @test !signcount_is_valid(57, 56)
    # Non-zero, not increasing (replay/duplicate)
    @test !signcount_is_valid(1, 1)

    # Always accept if new==0 (non-incrementing authenticators)
    @test signcount_is_valid(99, 0)
    @test signcount_is_valid(5, 0)
end