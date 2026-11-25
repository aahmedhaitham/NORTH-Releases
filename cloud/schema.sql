CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_sources (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    network TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cloud_events (
    source_id TEXT NOT NULL REFERENCES cloud_sources(id),
    id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    kind INTEGER NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (source_id, id)
);
CREATE INDEX IF NOT EXISTS cloud_events_time ON cloud_events (source_id, timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS cloud_events_workspace_time ON cloud_events (timestamp DESC);

CREATE TABLE IF NOT EXISTS cloud_cases (
    source_id TEXT NOT NULL REFERENCES cloud_sources(id),
    id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL,
    report TEXT NOT NULL,
    PRIMARY KEY (source_id, id)
);
CREATE INDEX IF NOT EXISTS cloud_cases_time ON cloud_cases (source_id, timestamp DESC, id DESC);

CREATE TABLE IF NOT EXISTS cloud_pairings (
    source_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

INSERT OR IGNORE INTO cloud_sources (id, label, network, updated_at)
SELECT 'legacy', 'Earlier collector', json_extract(payload, '$.network'), updated_at FROM snapshots;

INSERT OR IGNORE INTO cloud_events (source_id, id, timestamp, kind, payload)
SELECT 'legacy', json_extract(event.value, '$.id'), json_extract(event.value, '$.timestamp'),
       json_extract(event.value, '$.kind'), event.value
FROM snapshots, json_each(snapshots.payload, '$.events') AS event;

INSERT OR IGNORE INTO cloud_cases (source_id, id, timestamp, payload, report)
SELECT 'legacy', json_extract(item.value, '$.id'),
       coalesce(json_extract(item.value, '$.evidence[#-1].timestamp'), snapshots.updated_at),
       item.value, coalesce(json_extract(snapshots.payload, '$.reports.' || json_extract(item.value, '$.id')), '')
FROM snapshots, json_each(snapshots.payload, '$.cases') AS item;
