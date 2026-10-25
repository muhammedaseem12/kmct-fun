-- KMCT Community: private encrypted voice-message storage
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('voice-messages', 'voice-messages', false, 15728640, array['text/plain'])
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "KMCT voice uploads by conversation members" on storage.objects;
create policy "KMCT voice uploads by conversation members"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'voice-messages'
  and (storage.foldername(name))[1] = auth.uid()::text
  and exists (
    select 1
    from public.conversation_members cm
    where cm.user_id = auth.uid()
      and cm.conversation_id::text = (storage.foldername(name))[2]
  )
);

drop policy if exists "KMCT voice reads by conversation members" on storage.objects;
create policy "KMCT voice reads by conversation members"
on storage.objects for select to authenticated
using (
  bucket_id = 'voice-messages'
  and exists (
    select 1
    from public.conversation_members cm
    where cm.user_id = auth.uid()
      and cm.conversation_id::text = (storage.foldername(name))[2]
  )
);
