-- This database is intentionally insecure and must only be used for local tests.
GRANT CREATE ON SCHEMA public TO PUBLIC;

CREATE ROLE overly_privileged LOGIN CREATEDB CREATEROLE BYPASSRLS;
CREATE ROLE unlimited_app LOGIN;

ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;

CREATE TABLE public.example_sensitive_data (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    api_token text NOT NULL
);

GRANT SELECT, UPDATE ON public.example_sensitive_data TO PUBLIC;

CREATE FUNCTION public.lab_admin_action()
RETURNS integer
LANGUAGE sql
SECURITY DEFINER
AS 'SELECT 1';

CREATE TABLE public.rls_without_policy (tenant_id bigint, payload text);
ALTER TABLE public.rls_without_policy ENABLE ROW LEVEL SECURITY;
