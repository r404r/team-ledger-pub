-- Run as the v12 schema owner after migration. Roles are NOLOGIN until the
-- operator configures deployment-local authentication outside this file.
DO $$BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='teamledger_audit_receiver') THEN
    CREATE ROLE teamledger_audit_receiver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='teamledger_audit_forwarder') THEN
    CREATE ROLE teamledger_audit_forwarder NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='teamledger_audit_maintainer') THEN
    CREATE ROLE teamledger_audit_maintainer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='teamledger_audit_api_status') THEN
    CREATE ROLE teamledger_audit_api_status NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END$$;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM teamledger_audit_receiver,teamledger_audit_forwarder,teamledger_audit_maintainer,teamledger_audit_api_status;
GRANT USAGE ON SCHEMA public TO teamledger_audit_receiver,teamledger_audit_forwarder,teamledger_audit_maintainer,teamledger_audit_api_status;
GRANT SELECT ON schema_version TO teamledger_audit_receiver;
GRANT SELECT,INSERT,UPDATE ON audit_receiver_chain TO teamledger_audit_receiver;
GRANT SELECT,INSERT ON audit_receiver_ledger TO teamledger_audit_receiver;
GRANT SELECT ON audit_event,audit_outbox TO teamledger_audit_forwarder;
GRANT UPDATE ON audit_outbox TO teamledger_audit_forwarder;
GRANT SELECT,INSERT,UPDATE ON audit_receiver_status TO teamledger_audit_forwarder;
GRANT SELECT ON audit_receiver_ledger,audit_outbox TO teamledger_audit_maintainer;
GRANT SELECT ON audit_receiver_status TO teamledger_audit_api_status;
-- No role receives UPDATE/DELETE on audit_receiver_ledger. The offline
-- maintainer can only prove signer-retirement eligibility; the schema owner
-- remains an offline authority and MUST NOT be used by runtime services.
