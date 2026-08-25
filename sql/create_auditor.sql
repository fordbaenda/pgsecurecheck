\set ON_ERROR_STOP on

-- Run this file as a database administrator in every database to be assessed.
-- Set a password interactively afterwards with: \password pgsecurecheck_auditor

DO $pgsecurecheck$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'pgsecurecheck_auditor') THEN
        CREATE ROLE pgsecurecheck_auditor LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$pgsecurecheck$;

GRANT CONNECT ON DATABASE :DBNAME TO pgsecurecheck_auditor;

-- PostgreSQL restricts this view by default. This narrow grant enables the HBA check
-- without granting pg_read_all_settings, pg_monitor, or superuser privileges.
GRANT SELECT ON pg_catalog.pg_hba_file_rules TO pgsecurecheck_auditor;

