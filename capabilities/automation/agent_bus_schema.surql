-- Agent Bus Schema
-- namespace: agent_bus | database: prod
-- Hardened: parameterized bindings (callers use $param), name validation,
-- ed25519 signature field, TTL cleanup function. See bus_*.yaml for usage.

-- ── Namespace + Database ──────────────────────────────────────────────────────

DEFINE NAMESPACE IF NOT EXISTS agent_bus;
USE NAMESPACE agent_bus;
DEFINE DATABASE IF NOT EXISTS prod;
USE DATABASE prod;

-- ── bus_msg ───────────────────────────────────────────────────────────────────
-- Immutable message records. Each INSERT gets a ULID id.

DEFINE TABLE OVERWRITE bus_msg SCHEMAFULL;

DEFINE FIELD OVERWRITE ts             ON TABLE bus_msg TYPE datetime   DEFAULT time::now();
DEFINE FIELD OVERWRITE topic          ON TABLE bus_msg TYPE string     ASSERT $value != NONE AND $value != "";
DEFINE FIELD OVERWRITE from_agent     ON TABLE bus_msg TYPE string     ASSERT $value != NONE AND $value != "";
DEFINE FIELD OVERWRITE to_agent       ON TABLE bus_msg TYPE option<string>;
DEFINE FIELD OVERWRITE kind           ON TABLE bus_msg TYPE string     VALUE $value OR "event";
DEFINE FIELD OVERWRITE body           ON TABLE bus_msg TYPE object     VALUE $value OR {};
DEFINE FIELD OVERWRITE body.*         ON TABLE bus_msg TYPE any;
DEFINE FIELD OVERWRITE correlation_id ON TABLE bus_msg TYPE option<string>;
DEFINE FIELD OVERWRITE reply_to       ON TABLE bus_msg TYPE option<record<bus_msg>>;
DEFINE FIELD OVERWRITE ttl_s          ON TABLE bus_msg TYPE int        DEFAULT 86400;
-- ed25519 signature (base64-encoded, 88 chars). Verifier looks up sender pubkey
-- from bus_agent registry and checks signature over canonical message bytes.
DEFINE FIELD OVERWRITE signature      ON TABLE bus_msg TYPE option<string>;

DEFINE INDEX OVERWRITE bus_topic_ts   ON TABLE bus_msg COLUMNS topic, ts;
DEFINE INDEX OVERWRITE bus_to_ts      ON TABLE bus_msg COLUMNS to_agent, ts;

-- ── bus_agent ─────────────────────────────────────────────────────────────────
-- Agent registry. Upserted by bus_announce. id = bus_agent:<name>.
-- Name validation: lowercase alphanumeric plus . _ - : / @ + ; max 64 chars.
-- Rejects spaces, control chars, and exotic punctuation that would break topic
-- parsing or shell-escape rules in downstream tools.

DEFINE TABLE OVERWRITE bus_agent SCHEMAFULL;

DEFINE FIELD OVERWRITE ts_first       ON TABLE bus_agent TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE ts_last        ON TABLE bus_agent TYPE datetime DEFAULT time::now();
DEFINE FIELD OVERWRITE name           ON TABLE bus_agent TYPE string
    ASSERT $value != NONE
        AND string::len($value) > 0
        AND string::len($value) <= 64
        AND string::matches($value, '^[a-zA-Z0-9._:\\-/@+]+$');
DEFINE FIELD OVERWRITE provider       ON TABLE bus_agent TYPE string   VALUE $value OR "unknown";
DEFINE FIELD OVERWRITE host           ON TABLE bus_agent TYPE string   VALUE $value OR "";
DEFINE FIELD OVERWRITE capabilities   ON TABLE bus_agent TYPE array<string> VALUE $value OR [];
DEFINE FIELD OVERWRITE embedding      ON TABLE bus_agent TYPE option<array<float>>;
DEFINE FIELD OVERWRITE pubkey         ON TABLE bus_agent TYPE option<string>;
DEFINE FIELD OVERWRITE status         ON TABLE bus_agent TYPE string   VALUE $value OR "active";

DEFINE INDEX OVERWRITE bus_agent_name ON TABLE bus_agent COLUMNS name UNIQUE;

-- ── TTL cleanup ──────────────────────────────────────────────────────────────
-- Function: removes expired bus_msg rows (ts + ttl_s < now). Call periodically
-- from outside (cron, systemd timer, or a SurrealDB scheduled task once 3.x
-- exposes them). Returns the count of deleted rows for observability.

DEFINE FUNCTION OVERWRITE fn::bus_cleanup_expired() {
    LET $deleted = (
        DELETE bus_msg
        WHERE ts + duration::from_secs(ttl_s) < time::now()
        RETURN BEFORE
    );
    RETURN { deleted: array::len($deleted) };
};
