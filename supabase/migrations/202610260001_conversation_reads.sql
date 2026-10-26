-- Persistent per-account read receipts for private chats.
-- Safe to run in Supabase SQL Editor; creates only the new receipt table.
create table if not exists public.conversation_reads (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

alter table public.conversation_reads enable row level security;

drop policy if exists "Users can read their own conversation receipts" on public.conversation_reads;
create policy "Users can read their own conversation receipts"
on public.conversation_reads for select to authenticated
using (user_id = auth.uid());

drop policy if exists "Members can insert their own conversation receipts" on public.conversation_reads;
create policy "Members can insert their own conversation receipts"
on public.conversation_reads for insert to authenticated
with check (
  user_id = auth.uid()
  and exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = conversation_reads.conversation_id
      and cm.user_id = auth.uid()
  )
);

drop policy if exists "Members can update their own conversation receipts" on public.conversation_reads;
create policy "Members can update their own conversation receipts"
on public.conversation_reads for update to authenticated
using (user_id = auth.uid())
with check (
  user_id = auth.uid()
  and exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = conversation_reads.conversation_id
      and cm.user_id = auth.uid()
  )
);

grant select, insert, update on public.conversation_reads to authenticated;
