-- Agent Bus Schema
-- namespace: agent_bus | database: prod
-- Spike: auth=keypair-pending (from_agent taken as-stated, no ed25519 verification)
-- Production: requires ed25519 per design doc §4.4

-- ── Namespace + Database ──────────────────────────────────────────────────────

DEFINE NAMESPACE IF NOT EXISTS agent_bus;
USE NAMESPACE agent_bus;
DEFINE DATABASE IF NOT EXISTS prod;
USE DATABASE prod;

-- ── bus_msg ───────────────────────────────────────────────────────────────────
-- Immutable message records. Each INSERT gets a ULID id.

DEFINE TABLE bus_msg SCHEMAFULL;

DEFINE FIELD ts             ON TABLE bus_msg TYPE datetime   DEFAULT time::now();
DEFINE FIELD topic          ON TABLE bus_msg TYPE string     ASSERT $value != NONE AND $value != "";
DEFINE FIELD from_agent     ON TABLE bus_msg TYPE string     ASSERT $value != NONE AND $value != "";
DEFINE FIELD to_agent       ON TABLE bus_msg TYPE option<string>;
DEFINE FIELD kind           ON TABLE bus_msg TYPE string     VALUE $value OR "event";
DEFINE FIELD body           ON TABLE bus_msg TYPE object     VALUE $value OR {};
DEFINE FIELD body.*         ON TABLE bus_msg TYPE any;
DEFINE FIELD correlation_id ON TABLE bus_msg TYPE option<string>;
DEFINE FIELD reply_to       ON TABLE bus_msg TYPE option<record<bus_msg>>;
DEFINE FIELD ttl_s          ON TABLE bus_msg TYPE int        DEFAULT 86400;
DEFINE FIELD signature      ON TABLE bus_msg TYPE option<string>;

DEFINE INDEX bus_topic_ts   ON TABLE bus_msg COLUMNS topic, ts;
DEFINE INDEX bus_to_ts      ON TABLE bus_msg COLUMNS to_agent, ts;

-- ── bus_agent ─────────────────────────────────────────────────────────────────
-- Agent registry. Upserted by bus_announce. id = bus_agent:<name>.

DEFINE TABLE bus_agent SCHEMAFULL;

DEFINE FIELD ts_first       ON TABLE bus_agent TYPE datetime DEFAULT time::now();
DEFINE FIELD ts_last        ON TABLE bus_agent TYPE datetime DEFAULT time::now();
DEFINE FIELD name           ON TABLE bus_agent TYPE string   ASSERT $value != NONE AND $value != "";
DEFINE FIELD provider       ON TABLE bus_agent TYPE string   VALUE $value OR "unknown";
DEFINE FIELD host           ON TABLE bus_agent TYPE string   VALUE $value OR "";
DEFINE FIELD capabilities   ON TABLE bus_agent TYPE array<string> VALUE $value OR [];
DEFINE FIELD embedding      ON TABLE bus_agent TYPE option<array<float>>;
DEFINE FIELD pubkey         ON TABLE bus_agent TYPE option<string>;
DEFINE FIELD status         ON TABLE bus_agent TYPE string   VALUE $value OR "active";

DEFINE INDEX bus_agent_name ON TABLE bus_agent COLUMNS name UNIQUE;
