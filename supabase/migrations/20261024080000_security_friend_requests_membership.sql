-- KMCT Community security hardening.
-- Apply after reviewing in Supabase SQL Editor. This migration preserves existing data.
-- 1) Only the receiver may accept/decline a pending request.
--    The sender may only cancel their own pending request.
-- 2) Client-side membership inserts are restricted to global/group rooms.
--    Private conversations must be created through start_friend_conversation().
-- 3) This project uses 'private', not the legacy 'direct', conversation type.

begin;

-- Security-definer helper avoids recursive conversations RLS while checking room type.
create or replace function public.kmct_can_join_public_room(p_conversation_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.conversations c
    where c.id = p_conversation_id
      and c.conversation_type in ('global', 'group')
  );
$$;

revoke all on function public.kmct_can_join_public_room(uuid) from public, anon;
grant execute on function public.kmct_can_join_public_room(uuid) to authenticated;

-- Prevent arbitrary membership inserts into private conversations.
drop policy if exists "users can create own membership"
  on public.conversation_members;

create policy "users can create own membership"
on public.conversation_members
for insert
to authenticated
with check (
  user_id = (select auth.uid())
  and public.kmct_can_join_public_room(conversation_id)
);

-- Restrict status updates at the RLS layer.
drop policy if exists "receiver or sender updates request"
  on public.friend_requests;

create policy "receiver or sender updates request"
on public.friend_requests
for update
to authenticated
using (
  (receiver_id = (select auth.uid()) and status = 'pending')
  or (sender_id = (select auth.uid()) and status = 'pending')
)
with check (
  (receiver_id = (select auth.uid()) and status in ('accepted', 'declined'))
  or (sender_id = (select auth.uid()) and status = 'cancelled')
);

-- Enforce valid transitions and immutable participants even if another policy is added later.
create or replace function public.kmct_guard_friend_request_update()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
declare
  actor uuid := auth.uid();
begin
  if new.sender_id is distinct from old.sender_id
     or new.receiver_id is distinct from old.receiver_id then
    raise exception 'Cannot change friend request participants';
  end if;

  if actor is null then
    raise exception 'Sign in to update a friend request';
  end if;

  if old.status <> 'pending' then
    raise exception 'Only pending friend requests can be updated';
  end if;

  if actor = old.sender_id then
    if new.status <> 'cancelled' then
      raise exception 'Sender can only cancel a pending request';
    end if;
  elsif actor = old.receiver_id then
    if new.status not in ('accepted', 'declined') then
      raise exception 'Receiver can only accept or decline a pending request';
    end if;
  else
    raise exception 'Not allowed to update this friend request';
  end if;

  return new;
end;
$$;

drop trigger if exists kmct_guard_friend_request_update
  on public.friend_requests;

create trigger kmct_guard_friend_request_update
before update on public.friend_requests
for each row
execute function public.kmct_guard_friend_request_update();

commit;
