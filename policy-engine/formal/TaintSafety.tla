---- MODULE TaintSafety ----
EXTENDS Naturals

VARIABLES tainted, sanitized, reachedSink

Init ==
    /\ tainted = FALSE
    /\ sanitized = FALSE
    /\ reachedSink = FALSE

Taint ==
    /\ reachedSink = FALSE
    /\ tainted' = TRUE
    /\ UNCHANGED <<sanitized, reachedSink>>

Sanitize ==
    /\ tainted = TRUE
    /\ reachedSink = FALSE
    /\ sanitized' = TRUE
    /\ UNCHANGED <<tainted, reachedSink>>

GoToSink ==
    /\ (tainted = FALSE \/ sanitized = TRUE)
    /\ reachedSink' = TRUE
    /\ UNCHANGED <<tainted, sanitized>>

Next == Taint \/ Sanitize \/ GoToSink

Spec == Init /\ [][Next]_<<tainted, sanitized, reachedSink>>

SafetyInvariant ==
    reachedSink = TRUE => (tainted = FALSE \/ sanitized = TRUE)
====