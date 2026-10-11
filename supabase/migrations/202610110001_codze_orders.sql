-- CODZE Order Intake foundation
-- Review before running in Supabase SQL Editor. No public table access is granted.
create extension if not exists pgcrypto;

create type public.codze_order_status as enum (
  'new', 'in_progress', 'waiting_customer', 'completed', 'cancelled'
);

create type public.codze_notify_status as enum ('pending', 'sent', 'failed');

create table if not exists public.codze_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.codze_orders (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  name text not null check (char_length(name) between 2 and 80),
  contact_method text not null check (contact_method in ('email', 'whatsapp', 'phone')),
  contact text not null check (char_length(contact) between 1 and 80),
  project_type text not null check (project_type in ('cards', 'web', 'menus', 'brand', 'other')),
  message text not null check (char_length(message) between 10 and 600),
  status public.codze_order_status not null default 'new',
  admin_notes text not null default '' check (char_length(admin_notes) <= 2000),
  notify_status public.codze_notify_status not null default 'pending',
  notify_attempts integer not null default 0 check (notify_attempts >= 0),
  notify_error_code text null check (notify_error_code is null or char_length(notify_error_code) <= 80),
  idempotency_key uuid not null unique default gen_random_uuid()
);

create table if not exists public.codze_rate_limits (
  ip_hash text primary key check (char_length(ip_hash) between 32 and 128),
  window_started_at timestamptz not null default now(),
  request_count integer not null default 1 check (request_count >= 0),
  updated_at timestamptz not null default now()
);

create index if not exists codze_orders_created_at_idx on public.codze_orders (created_at desc);
create index if not exists codze_orders_status_created_at_idx on public.codze_orders (status, created_at desc);
create index if not exists codze_orders_notify_status_idx on public.codze_orders (notify_status) where notify_status <> 'sent';

alter table public.codze_admins enable row level security;
alter table public.codze_orders enable row level security;
alter table public.codze_rate_limits enable row level security;

-- Intentionally no anon/authenticated policies on orders or rate limits.
-- The Edge Function uses the server-side service role key, never the browser.
-- Admin dashboard policies are added only after the single admin Auth user is created
-- and its exact user UUID is reviewed. This avoids accidentally exposing customer data.

create or replace function public.codze_set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists codze_orders_updated_at on public.codze_orders;
create trigger codze_orders_updated_at
before update on public.codze_orders
for each row execute function public.codze_set_updated_at();

comment on table public.codze_orders is 'Private CODZE customer inquiries. Access through the Edge Function and explicitly authorized admin only.';
comment on table public.codze_admins is 'Allowlist of authenticated CODZE admin users; populate only after verifying the admin Auth UUID.';
comment on table public.codze_rate_limits is 'Private server-side rate limit counters keyed by a salted hash, not raw IP addresses.';
