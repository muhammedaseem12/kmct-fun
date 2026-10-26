-- Mutual /clear requests: the second participant's request clears the
-- conversation's full message history for both accounts.
create table if not exists public.conversation_clear_requests (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  requested_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);

alter table public.conversation_clear_requests enable row level security;
revoke all on public.conversation_clear_requests from anon, authenticated;

create or replace function public.request_private_chat_clear(p_conversation_id uuid)
returns text
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_user_id uuid := auth.uid();
  v_member_count integer;
  v_request_count integer;
begin
  if v_user_id is null then
    raise exception 'You must be signed in to clear a private chat.';
  end if;

  -- Serialize requests for this conversation so simultaneous requests cannot race.
  perform 1
  from public.conversations c
  where c.id = p_conversation_id
  for update;

  if not found then
    raise exception 'Conversation not found.';
  end if;

  select count(*) into v_member_count
  from public.conversation_members cm
  where cm.conversation_id = p_conversation_id;

  if v_member_count <> 2 then
    raise exception 'This command is only available for a two-person private chat.';
  end if;

  if not exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = p_conversation_id
      and cm.user_id = v_user_id
  ) then
    raise exception 'You are not a member of this conversation.';
  end if;

  insert into public.conversation_clear_requests (conversation_id, user_id, requested_at)
  values (p_conversation_id, v_user_id, now())
  on conflict (conversation_id, user_id)
  do update set requested_at = excluded.requested_at;

  select count(*) into v_request_count
  from public.conversation_clear_requests r
  where r.conversation_id = p_conversation_id;

  if v_request_count < 2 then
    return 'requested';
  end if;

  delete from public.messages m
  where m.conversation_id = p_conversation_id;

  delete from public.conversation_clear_requests r
  where r.conversation_id = p_conversation_id;

  return 'cleared';
end;
$$;

revoke all on function public.request_private_chat_clear(uuid) from public, anon;
grant execute on function public.request_private_chat_clear(uuid) to authenticated;
