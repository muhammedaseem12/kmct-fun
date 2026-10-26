-- Extend mutual /clear so it also removes encrypted voice files from Storage.
-- Text and voice message rows are deleted together after both participants request clear.
create or replace function public.request_private_chat_clear(p_conversation_id uuid)
returns text
language plpgsql
security definer
set search_path = public, auth, storage
as $$
declare
  v_user_id uuid := auth.uid();
  v_member_count integer;
  v_request_count integer;
begin
  if v_user_id is null then
    raise exception 'You must be signed in to clear a private chat.';
  end if;

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
    raise exception 'This command is only available in a two-person private chat.';
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

  -- Remove encrypted voice objects referenced by this conversation's messages.
  delete from storage.objects o
  where o.bucket_id = 'voice-messages'
    and o.name in (
      select substring(m.body from 11)
      from public.messages m
      where m.conversation_id = p_conversation_id
        and m.body like 'E2EEVOICE:%'
    );

  -- Remove all private messages, both text and voice references.
  delete from public.messages m
  where m.conversation_id = p_conversation_id;

  delete from public.conversation_clear_requests r
  where r.conversation_id = p_conversation_id;

  return 'cleared';
end;
$$;

revoke all on function public.request_private_chat_clear(uuid) from public, anon;
grant execute on function public.request_private_chat_clear(uuid) to authenticated;
