DROP DATABASE IF EXISTS tenable;
CREATE DATABASE tenable;

\c tenable

CREATE TABLE IF NOT EXISTS assets (
    jdoc JSONB NOT NULL
);
CREATE INDEX assetidx ON assets USING GIN (jdoc);

CREATE TABLE IF NOT EXISTS vulns (
    jdoc JSONB NOT NULL
);
CREATE INDEX vulnidx ON vulns USING GIN (jdoc);

CREATE TABLE IF NOT EXISTS scans (
    jdoc JSONB NOT NULL
);
CREATE INDEX scanidx ON vulns USING GIN (jdoc);

CREATE TABLE IF NOT EXISTS policies (
    jdoc JSONB NOT NULL
);
CREATE INDEX policyidx ON vulns USING GIN (jdoc);

CREATE TABLE IF NOT EXISTS export_jobs (
    id SERIAL,
    checkpoint TIMESTAMP,
    job_start TIMESTAMP,
    job_end TIMESTAMP
);






