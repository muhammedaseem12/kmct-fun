-- KMCT Community live social features migration
-- Run in Supabase SQL Editor after schema.sql. Safe to re-run.
create extension if not exists pgcrypto;

alter table public.conversations add column if not exists conversation_type text not null default 'private'
  check (conversation_type in ('global','private','group'));
alter table public.conversations add column if not exists title text;
-- Conversation IDs are already unique; private chats use conversation_type = 'private'.

-- Avoid recursive RLS when checking conversation membership.
create or replace function public.is_conversation_member(p_conversation uuid, p_user uuid default auth.uid())
returns boolean language sql stable security definer set search_path = ''
as $$ select exists (
  select 1 from public.conversation_members cm
  where cm.conversation_id = p_conversation and cm.user_id = p_user
); $$;

-- Direct messages are created only between accepted friends.
create or replace function public.start_friend_conversation(p_friend uuid)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_conversation uuid;
begin
  if auth.uid() is null or p_friend = auth.uid() then
    raise exception 'Sign in and choose another member.';
  end if;
  if not public.are_friends(auth.uid(), p_friend) then
    raise exception 'You can message only after the friend request is accepted.';
  end if;

  select c.id into v_conversation
  from public.conversations c
  join public.conversation_members a on a.conversation_id=c.id and a.user_id=auth.uid()
  join public.conversation_members b on b.conversation_id=c.id and b.user_id=p_friend
  where c.conversation_type='private'
  limit 1;

  if v_conversation is null then
    insert into public.conversations(conversation_type) values ('private') returning id into v_conversation;
    insert into public.conversation_members(conversation_id,user_id)
      values (v_conversation,auth.uid()),(v_conversation,p_friend);
  end if;
  return v_conversation;
end; $$;

-- A single global group chat is available to authenticated users.
create or replace function public.join_global_chat()
returns uuid language plpgsql security definer set search_path = ''
as $$
declare v_conversation uuid;
begin
  if auth.uid() is null then raise exception 'Sign in first.'; end if;
  select id into v_conversation from public.conversations
    where conversation_type='group' and title='KMCT Global Chat' limit 1;
  if v_conversation is null then
    insert into public.conversations(conversation_type,title)
      values ('group','KMCT Global Chat') returning id into v_conversation;
  end if;
  insert into public.conversation_members(conversation_id,user_id)
    values(v_conversation,auth.uid()) on conflict do nothing;
  return v_conversation;
end; $$;

create or replace function public.is_friend_request_participant(p_request uuid)
returns boolean language sql stable security definer set search_path = ''
as $$ select exists (
  select 1 from public.friend_requests fr where fr.id=p_request
  and (fr.sender_id=auth.uid() or fr.receiver_id=auth.uid())
); $$;

-- Tighten membership and messaging permissions.
drop policy if exists "members can see membership" on public.conversation_members;
create policy "members can see membership" on public.conversation_members
for select to authenticated using (public.is_conversation_member(conversation_id, auth.uid()));

drop policy if exists "users can create own membership" on public.conversation_members;
create policy "users can create own membership" on public.conversation_members
for insert to authenticated with check (
  user_id=auth.uid()
  and exists (select 1 from public.conversations c where c.id=conversation_id and c.conversation_type='group')
);

drop policy if exists "conversation members read conversations" on public.conversations;
create policy "conversation members read conversations" on public.conversations
for select to authenticated using (public.is_conversation_member(id, auth.uid()));

drop policy if exists "conversation members read messages" on public.messages;
create policy "conversation members read messages" on public.messages
for select to authenticated using (public.is_conversation_member(conversation_id, auth.uid()));

drop policy if exists "members send messages only as self" on public.messages;
create policy "members send messages only as self" on public.messages
for insert to authenticated with check (
  sender_id=auth.uid() and public.is_conversation_member(conversation_id, auth.uid())
);

grant execute on function public.start_friend_conversation(uuid) to authenticated;
grant execute on function public.join_global_chat() to authenticated;
grant execute on function public.is_conversation_member(uuid,uuid) to authenticated;

-- Realtime: add messages and user_presence to the Supabase Realtime publication if not already present.
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='user_presence') then
    alter publication supabase_realtime add table public.user_presence;
  end if;
exception when undefined_object then
  raise notice 'supabase_realtime publication not found; enable Realtime in Supabase dashboard.';
end $$;
