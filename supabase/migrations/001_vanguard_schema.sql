create table if not exists public.vanguard_cases (
 case_key text primary key, title text not null, severity text not null,
 status text not null default 'OPEN', owner text not null default '',
 evidence_sha256 text not null default '', summary text not null default '',
 created_at timestamptz not null, updated_at timestamptz not null
);
create table if not exists public.vanguard_iocs (
 indicator text not null, indicator_type text not null,
 source text not null default 'LOCAL', confidence text not null default 'UNKNOWN',
 first_seen timestamptz, last_seen timestamptz, expires_at timestamptz,
 tags_json jsonb not null default '[]'::jsonb, primary key(indicator,indicator_type)
);
create table if not exists public.vanguard_vulnerabilities (
 vuln_key text primary key, cve text, asset_key text not null,
 severity text not null default 'UNKNOWN', cvss double precision,
 status text not null default 'OPEN', discovered_at timestamptz not null,
 due_at timestamptz, source text not null default 'LOCAL',
 details_json jsonb not null default '{}'::jsonb
);
create table if not exists public.vanguard_playbooks (
 playbook_key text primary key, name text not null, version text not null,
 enabled boolean not null default true, approval_required boolean not null default true,
 steps_json jsonb not null default '[]'::jsonb, updated_at timestamptz not null
);
create table if not exists public.vanguard_playbook_runs (
 run_key text primary key, playbook_key text not null, status text not null,
 approved boolean not null default false, requested_by text not null default '',
 started_at timestamptz not null, completed_at timestamptz,
 result_json jsonb not null default '{}'::jsonb
);
create table if not exists public.vanguard_ueba_observations (
 observation_key text primary key, entity_key text not null, entity_type text not null,
 anomaly_type text not null, score double precision not null, observed_at timestamptz not null,
 evidence_sha256 text not null default '', details_json jsonb not null default '{}'::jsonb
);
create table if not exists public.vanguard_compliance_mappings (
 control_key text primary key, framework text not null, title text not null,
 status text not null default 'NOT_ASSESSED',
 evidence_refs_json jsonb not null default '[]'::jsonb,
 owner text not null default '', reviewed_at timestamptz
);
alter table public.vanguard_cases enable row level security;
alter table public.vanguard_iocs enable row level security;
alter table public.vanguard_vulnerabilities enable row level security;
alter table public.vanguard_playbooks enable row level security;
alter table public.vanguard_playbook_runs enable row level security;
alter table public.vanguard_ueba_observations enable row level security;
alter table public.vanguard_compliance_mappings enable row level security;
