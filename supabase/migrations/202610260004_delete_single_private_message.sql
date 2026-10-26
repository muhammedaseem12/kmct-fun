-- Allow a sender to delete one of their own private text or encrypted voice messages.
-- Voice objects are removed from the voice-messages bucket as part of the same request.
create or replace function public.delete_private_message(p_message_id uuid)
returns text
language plpgsql
security definer
set search_path = public, auth, storage
as $$
declare
  v_user_id uuid := auth.uid();
  v_conversation_id uuid;
  v_body text;
begin
  if v_user_id is null then
    raise exception 'You must be signed in.';
  end if;

  select m.conversation_id, m.body
    into v_conversation_id, v_body
  from public.messages m
  join public.conversation_members cm
    on cm.conversation_id = m.conversation_id
   and cm.user_id = v_user_id
  where m.id = p_message_id
    and m.sender_id = v_user_id
  for update of m;

  if not found then
    raise exception 'Message not found, or you can only delete messages you sent.';
  end if;

  if v_body like 'E2EEVOICE:%' then
    delete from storage.objects o
    where o.bucket_id = 'voice-messages'
      and o.name = substring(v_body from 11);
  end if;

  delete from public.messages
  where id = p_message_id
    and conversation_id = v_conversation_id
    and sender_id = v_user_id;

  return 'deleted';
end;
$$;

revoke all on function public.delete_private_message(uuid) from public, anon;
grant execute on function public.delete_private_message(uuid) to authenticated;
