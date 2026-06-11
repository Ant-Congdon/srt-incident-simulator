-- supabase_setup.sql
-- ====================
-- Run this in the Supabase SQL editor (your project > SQL Editor > New query).
-- It creates the table that stores completed student sessions.
-- The Netlify function writes to this table after [[DP:DONE]] is reached.

-- Create the sessions table
create table if not exists sessions (
  id              bigint generated always as identity primary key,
  student_name    text,
  student_id      text,
  incident_type   text,
  sitrep          text,       -- JSON string of all SitRep fields
  logbook         text,       -- plain text logbook entries
  transcript      text,       -- full chat transcript
  completed_at    timestamptz default now()
);

-- Allow the service role (used by the Netlify function) to insert rows.
-- The anon role gets no access - only your service key can write.
alter table sessions enable row level security;

create policy "Service role can insert"
  on sessions for insert
  to service_role
  with check (true);

-- If you want to view submissions in the Supabase dashboard,
-- you can query the table directly there. No extra policy is needed
-- for dashboard access when you are logged in as the project owner.

-- Optional: create an index on student_id for quick lookup
create index if not exists sessions_student_id_idx on sessions (student_id);
create index if not exists sessions_completed_at_idx on sessions (completed_at desc);
