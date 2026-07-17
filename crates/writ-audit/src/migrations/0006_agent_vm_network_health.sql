-- Agent-VM network-health transition events.
--
-- A running agent VM can lose its host<->guest network path: the macOS vmnet
-- bridge backing the session's `container` network can disappear (e.g. across
-- a host sleep/wake), so the broker gateway alias vanishes from every host
-- interface and the guest can no longer reach the broker -- while `container`
-- still reports the VM/network as running. The daemon detects this from the
-- HOST side (it never probes the untrusted guest) and, on a debounced change
-- in a session's reachability, appends one row here.
--
-- Append-only: the DAO has no UPDATE or DELETE path. Only host-derived values
-- are stored (an enum and a counter), never any bytes from the guest. The
-- rowid is the identity; there is no externally-referenced id.
CREATE TABLE agent_vm_network_health_event (
    event_id    INTEGER PRIMARY KEY,
    session_id  TEXT NOT NULL REFERENCES session(session_id),
    observed_at INTEGER NOT NULL,
    from_health TEXT NOT NULL CHECK (from_health IN ('reachable', 'unreachable', 'unknown')),
    to_health   TEXT NOT NULL CHECK (to_health   IN ('reachable', 'unreachable', 'unknown')),
    -- Consecutive unreachable observations at the moment of the transition.
    consecutive_failures INTEGER NOT NULL CHECK (consecutive_failures >= 0),
    -- A recorded event must actually be a transition.
    CHECK (from_health != to_health)
);

CREATE INDEX idx_agent_vm_network_health_event_session
    ON agent_vm_network_health_event(session_id, observed_at);

-- Mirror the proxy/provision tables: an event can only be written while the
-- referenced session is open, so a session's `closed_at` stays a true upper
-- bound on its activity window. A probe racing session teardown fails closed
-- here (the DAO treats the abort as best-effort and warns).
CREATE TRIGGER agent_vm_network_health_event_requires_open_session
BEFORE INSERT ON agent_vm_network_health_event
WHEN EXISTS (
    SELECT 1 FROM session
    WHERE session_id = NEW.session_id AND closed_at IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'session is closed');
END;
