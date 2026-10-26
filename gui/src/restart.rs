//! Pure restart-completion logic. Kept out of `main.rs` so the unit tests use the standard
//! `#[test]` (the `gpui::*` glob there shadows it).
//!
//! Primary signal — the engine reports it is *running* the saved config: its running-config digest
//! (from a status poll) matches the digest the save returned. This keys off the engine's own state
//! rather than the GUI catching the brief management-pipe drop, so a fast in-place restart that
//! drops and reconnects between two ~1 s polls is still detected.
//!
//! Fallback for a digest-less (older) service — which omits both digests on the wire — the GUI has
//! nothing to match, so it falls back to the prior drop/reconnect observation: complete once the
//! engine is reachable again after we saw it drop. That path is racy for a sub-poll restart (the
//! very reason for the digest signal), but it is correct for the common case and strictly better
//! than never completing and leaving the UI stuck in "restart needed".

/// Whether a pending restart is complete, given the `target` running-config digest a save returned,
/// the `running` digest from the latest status poll, whether we have `saw_drop` (seen the engine
/// unreachable since the in-place restart was triggered), and whether it is `reachable` now.
///
/// The caller only consults this while a restart is pending (it gates on `restart_needed`).
pub fn restart_completed(
    target: Option<u64>,
    running: Option<u64>,
    saw_drop: bool,
    reachable: bool,
) -> bool {
    match target {
        // Digest-aware peer: complete iff the engine reports running the saved config. Robust to a
        // fast in-place restart whose pipe drop falls between polls; the drop signal is irrelevant.
        Some(t) => running == Some(t),
        // Digest-less (older) peer: no running digest to compare, so fall back to drop/reconnect —
        // complete once reachable again after an observed drop.
        None => saw_drop && reachable,
    }
}

/// The restart-completion target to wait for this poll. While `tracking` a restart, prefer the
/// engine's latest `saved_digest` (the digest it will report running once the restart applies) — so
/// a NEWER save (another client, or a reload) advances the target instead of leaving it pinned to a
/// digest the GUI captured earlier, which would never match and stick the UI in "restart needed".
/// The caller refreshes EVERY poll while it is tracking a restart, NOT only while the engine reports
/// the pending state — so a restart that the GUI never observed mid-flight (another client's save +
/// an engine restart between two polls) still completes.
///
/// `saved_digest` is `None` against an intermediate-version service that reports the older digests
/// but not this one. There we fall back to `base_digest` — the last-saved digest the GUI holds from
/// its latest `GetConfig`/save, which IS the digest the engine reports running once the pending
/// restart applies — BEFORE the stale `current` target. Preferring `base_digest` over `current`
/// matters when the saved config advanced after the target was first set (another client saved B and
/// the user reloaded, so base_digest = B): the target must follow to B, not stay stuck on the old A.
/// (`current` is only the last resort, for the unlikely case of no base digest yet.) Only when no
/// digest source exists at all do we leave it `None` (completion then uses the legacy drop/reconnect
/// fallback in [`restart_completed`]). A modern peer always supplies `saved_digest`, so this
/// base-vs-current ordering never affects it.
pub fn refreshed_restart_target(
    tracking: bool,
    saved_digest: Option<u64>,
    current: Option<u64>,
    base_digest: Option<u64>,
) -> Option<u64> {
    if tracking {
        saved_digest.or(base_digest).or(current)
    } else {
        current
    }
}

/// Whether the engine is reachable on a poll tick: true if EITHER the Status leg OR the
/// ListConnections leg answered. The two are independent IPC calls; driving reachability off only
/// the ListConnections leg let a flapping list call mark a live engine unreachable — which discarded
/// the Status leg's restart-completion digest (stalling completion) and, for a digest-less peer,
/// manufactured a spurious engine "drop" via [`restart_completed`]'s drop/reconnect fallback.
pub fn engine_reachable(status_ok: bool, list_ok: bool) -> bool {
    status_ok || list_ok
}

/// Whether ANY poll leg failed this tick (Status or ListConnections) — the drop signal a
/// digest-less restart's drop/reconnect fallback needs, kept SEPARATE from [`engine_reachable`].
/// Status is polled before ListConnections, so a legacy service can restart between them (Status
/// succeeds, ListConnections fails): `engine_reachable` stays true (Status answered) and would miss
/// the drop, but this returns true, so the drop is recorded and the restart completes on a later
/// good poll instead of stalling until the deadline. (A digest-aware peer ignores this — it
/// completes on the running-config digest.)
pub fn any_poll_leg_failed(status_ok: bool, list_ok: bool) -> bool {
    !status_ok || !list_ok
}

/// One poll of the restart-completion state machine, with the drop and the completion DECOUPLED
/// across polls.
///
/// `prev_saw_drop` is the drop observed on EARLIER polls; completion is decided against THAT, NOT
/// against `dropped` (this poll's leg failure). Status is polled before ListConnections, so a single
/// Status-ok/List-fail tick IS the drop, not a reconnect — deciding completion on the prior state
/// means the poll that first observes a drop can never also complete it (drop and reconnect must be
/// separate polls). `dropped` is folded into `saw_drop_next` for the next poll. A digest-aware peer
/// (`target` Some) ignores all of this and completes immediately on a running-config digest match.
pub struct RestartStep {
    pub completed: bool,
    pub saw_drop_next: bool,
}

pub fn step_restart(
    target: Option<u64>,
    running: Option<u64>,
    prev_saw_drop: bool,
    dropped: bool,
    reachable: bool,
) -> RestartStep {
    RestartStep {
        completed: restart_completed(target, running, prev_saw_drop, reachable),
        saw_drop_next: prev_saw_drop || dropped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_restart_drop_and_reconnect_must_be_separate_polls() {
        // Digest-less peer. Poll 1: Status ok, List fail → this poll OBSERVES the drop, but that is
        // not a reconnect (the List failure IS the drop). It must NOT complete; it only records it.
        let p1 = step_restart(None, None, false, true, true);
        assert!(
            !p1.completed,
            "the poll that first observes the drop must not also complete the restart"
        );
        assert!(
            p1.saw_drop_next,
            "but it records the drop for the next poll"
        );
        // Poll 2: both legs answer (the reconnect). The prior drop + reachable now completes it.
        let p2 = step_restart(None, None, p1.saw_drop_next, false, true);
        assert!(
            p2.completed,
            "the next reachable poll completes the restart"
        );
    }

    #[test]
    fn step_restart_digest_match_completes_immediately() {
        // A digest-aware peer completes the moment running == target, with no observed drop needed.
        assert!(step_restart(Some(0xABC), Some(0xABC), false, false, true).completed);
    }

    #[test]
    fn step_restart_never_dropped_never_completes() {
        // Digest-less, stayed reachable the whole time, never saw a drop → never completes (a peer
        // that never dropped didn't actually restart).
        assert!(!step_restart(None, None, false, false, true).completed);
    }

    #[test]
    fn engine_reachable_when_either_poll_leg_answers() {
        assert!(engine_reachable(true, true));
        // Status answered but ListConnections failed: the engine stays reachable, so the Status leg's
        // restart-completion digest is retained. Whether that single-leg failure counts as a restart
        // "drop" is a SEPARATE decision (see any_poll_leg_failed / step_restart), not reachability.
        assert!(engine_reachable(true, false));
        assert!(engine_reachable(false, true));
        // Only when BOTH legs fail is the engine actually unreachable.
        assert!(!engine_reachable(false, false));
    }

    #[test]
    fn any_poll_leg_failed_catches_a_single_leg_drop_that_reachable_misses() {
        // Both legs answered → no drop.
        assert!(!any_poll_leg_failed(true, true));
        // The key case: Status answered, ListConnections failed (a legacy service restarting between
        // the two calls). The drop MUST be recorded even though the engine reads as reachable.
        assert!(any_poll_leg_failed(true, false));
        assert!(engine_reachable(true, false)); // reachability is independently still true
        assert!(any_poll_leg_failed(false, true));
        assert!(any_poll_leg_failed(false, false));
    }

    #[test]
    fn pending_restart_target_tracks_the_latest_saved_digest() {
        // Adopt a pending restart on saved config A.
        assert_eq!(
            refreshed_restart_target(true, Some(0xA), None, None),
            Some(0xA)
        );
        // A newer save (another client / a reload) advances the saved digest to B while still
        // pending → the target we wait for follows to B, instead of staying stuck on A.
        assert_eq!(
            refreshed_restart_target(true, Some(0xB), Some(0xA), None),
            Some(0xB)
        );
        // Engine reports no saved digest this poll → keep the current target.
        assert_eq!(
            refreshed_restart_target(true, None, Some(0xA), None),
            Some(0xA)
        );
        // Not tracking → unchanged; completion is decided by restart_completed.
        assert_eq!(
            refreshed_restart_target(false, Some(0xC), Some(0xB), None),
            Some(0xB)
        );
    }

    #[test]
    fn intermediate_service_without_saved_digest_falls_back_to_base_digest() {
        // A fresh session adopts a pending restart from an intermediate-version service that reports
        // running_config_digest + pending_restart_scope but NOT saved_config_digest. We have no saved
        // digest and no prior target, but base_digest (from GetConfig) is the last-saved digest — the
        // digest the engine reports running once the pending restart applies. Use it as the target so
        // completion stays digest-driven instead of dropping to the racy legacy drop/reconnect path.
        assert_eq!(
            refreshed_restart_target(true, None, None, Some(0xBA5E)),
            Some(0xBA5E)
        );
        // …and the restart then completes when running matches that base digest.
        assert!(restart_completed(Some(0xBA5E), Some(0xBA5E), false, true));
        // Only with NO digest source at all do we leave it None (legacy drop/reconnect fallback).
        assert_eq!(refreshed_restart_target(true, None, None, None), None);

        // Bug guard: an old target A was already set, then another client saved B and the user
        // reloaded so base_digest = B. base_digest must win over the STALE `current` A — otherwise
        // the GUI waits on A forever while the engine runs B.
        assert_eq!(
            refreshed_restart_target(true, None, Some(0xA), Some(0xB)),
            Some(0xB)
        );
        assert!(restart_completed(Some(0xB), Some(0xB), false, true));
        // But with no newer base digest (base None), keep the current target rather than regressing.
        assert_eq!(
            refreshed_restart_target(true, None, Some(0xA), None),
            Some(0xA)
        );
    }

    #[test]
    fn restart_completes_on_the_latest_target_after_an_advancing_save() {
        // Pending on A, then a save advances the saved config to B before the restart.
        let target = refreshed_restart_target(true, Some(0xA), None, None);
        let target = refreshed_restart_target(true, Some(0xB), target, None);
        assert_eq!(target, Some(0xB));
        // Still running the OLD config A → not complete.
        assert!(!restart_completed(target, Some(0xA), false, true));
        // Engine restarts and runs B (the latest saved) → complete, not stuck waiting on A.
        assert!(restart_completed(target, Some(0xB), false, true));
    }

    #[test]
    fn restart_completes_even_when_the_pending_state_was_never_observed() {
        // Tracking a restart with target A. Another client saves B and the engine restarts BETWEEN
        // our polls, so the next Status is already in sync (saved == running == B, pending None).
        // Because the caller refreshes while merely TRACKING a restart (not only while pending), the
        // target advances to B and completion registers — instead of sticking forever on A.
        let target = Some(0xA);
        let target = refreshed_restart_target(true, Some(0xB), target, None); // tracking → advance to B
        assert_eq!(target, Some(0xB));
        assert!(restart_completed(target, Some(0xB), false, true)); // running == B → complete
    }

    #[test]
    fn modern_peer_matches_on_digest_ignoring_drop_signal() {
        let target = Some(7);
        // Not live yet: engine still on the old config, or an unreachable poll — regardless of drop.
        assert!(!restart_completed(target, Some(3), false, true));
        assert!(!restart_completed(target, None, true, false));
        // Running the saved config → complete. The fast path (no drop seen) and the drop path agree,
        // so a fast in-place restart whose pipe drop fell between polls is still detected.
        assert!(restart_completed(target, Some(7), false, true));
        assert!(restart_completed(target, Some(7), true, true));
    }

    #[test]
    fn legacy_peer_falls_back_to_drop_then_reconnect() {
        // Digest-less service (target None, running None): complete only after a drop is observed
        // and the engine is reachable again — the documented backward-compat fallback.
        assert!(!restart_completed(None, None, false, true)); // fast restart, no drop seen → can't tell
        assert!(!restart_completed(None, None, true, false)); // dropped, not back up yet
        assert!(restart_completed(None, None, true, true)); // reconnected after the drop → complete
    }

    #[test]
    fn never_completes_without_a_drop_or_a_match() {
        // No restart actually applied: digest-less peer that never dropped, and a stray digest with
        // no pending target. (The caller additionally gates on restart_needed.)
        assert!(!restart_completed(None, Some(100), false, true));
        assert!(!restart_completed(Some(100), Some(99), true, true));
    }
}
