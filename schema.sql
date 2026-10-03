-- CHATTY database. Paste ALL of this into Supabase > SQL Editor > Run.
-- STEP FIRST: change CHANGE-THIS-PASSPHRASE below to your own secret words.

create table public.profiles(
 id uuid primary key references auth.users(id) on delete cascade,
 username text not null,
 created_at timestamptz not null default now(),
 muted text[] not null default '{}',
 mute_pct int not null default 30 check (mute_pct between 0 and 100),
 show_welcome boolean not null default true,
 last_login timestamptz);
create unique index profiles_username_key on public.profiles (lower(username));

create table public.messages(
 id bigint generated always as identity primary key,
 user_id uuid not null references public.profiles(id) on delete cascade,
 username text not null,
 body text not null check (char_length(body) between 2 and 1500),
 is_action boolean not null default false,
 created_at timestamptz not null default now());
create index messages_created_idx on public.messages(created_at);

create table public.invites(code text primary key, created_at timestamptz not null default now(), used_at timestamptz, used_by uuid);
create table public.requests(id bigint generated always as identity primary key, why text, who text, contact text, created_at timestamptz not null default now());
create table public.config(key text primary key, value text not null);
insert into public.config values ('admin_pass','CHANGE-THIS-PASSPHRASE');

alter table public.profiles enable row level security;
alter table public.messages enable row level security;
alter table public.invites enable row level security;
alter table public.requests enable row level security;
alter table public.config enable row level security;
create policy "members read profiles" on public.profiles for select to authenticated using (true);
create policy "members read recent messages" on public.messages for select to authenticated using (created_at > now() - interval '60 days');
-- (no other policies: everything else goes through the functions below)

alter publication supabase_realtime add table public.messages;

create function public.delay_for(n int) returns interval language sql immutable as $$
 select (case when n<=15 then 0.2 when n<=50 then 0.5 when n<=150 then 1 when n<=400 then 2 when n<=800 then 4 else 8 end) * interval '1 second' $$;

create function public.check_invite(c text) returns text language plpgsql security definer set search_path=public as $$
declare i public.invites;
begin
 c := upper(trim(coalesce(c,'')));
 if c !~ '^[A-Z0-9]{5}-[A-Z0-9]{5}-NORMAL$' then return 'format'; end if;
 select * into i from public.invites where code=c;
 if not found then return 'missing'; end if;
 if i.used_at is not null then return 'used'; end if;
 if i.created_at < now() - interval '3 days' then return 'expired'; end if;
 return 'ok';
end $$;

create function public.username_free(n text) returns boolean language sql security definer set search_path=public as $$
 select not exists(select 1 from public.profiles where lower(username)=lower(n)) $$;

-- Nobody can make an account without a valid invite, even by skipping the website.
create function public.guard_signup() returns trigger language plpgsql security definer set search_path=public as $$
declare u text := new.raw_user_meta_data->>'username'; c text := upper(coalesce(new.raw_user_meta_data->>'invite',''));
begin
 if u is null or u !~ '^[A-Za-z0-9_-]{3,24}$' or lower(new.email) <> lower(u)||'@chatty.invalid' then raise exception 'bad username'; end if;
 if not public.username_free(u) then raise exception 'username taken'; end if;
 if public.check_invite(c) <> 'ok' then raise exception 'bad invite'; end if;
 update public.invites set used_at=now() where code=c;
 return new;
end $$;
create trigger guard_signup before insert on auth.users for each row execute function public.guard_signup();

create function public.make_profile() returns trigger language plpgsql security definer set search_path=public as $$
begin
 insert into public.profiles(id,username) values (new.id,new.raw_user_meta_data->>'username');
 update public.invites set used_by=new.id where code=upper(new.raw_user_meta_data->>'invite');
 return new;
end $$;
create trigger make_profile after insert on auth.users for each row execute function public.make_profile();

create function public.post_message(b text, act boolean default false) returns public.messages language plpgsql security definer set search_path=public as $$
declare uid uuid := auth.uid(); p public.profiles; l public.messages; r public.messages; t text := trim(coalesce(b,''));
begin
 if uid is null then raise exception 'not signed in'; end if;
 select * into p from public.profiles where id=uid;
 if not found then raise exception 'no profile'; end if;
 if char_length(t) not between 2 and 1500 then raise exception 'bad length'; end if;
 select * into l from public.messages where user_id=uid order by created_at desc limit 1;
 if found and now() - l.created_at < public.delay_for(char_length(l.body)) - interval '150 milliseconds' then raise exception 'slow_down'; end if;
 insert into public.messages(user_id,username,body,is_action) values (uid,p.username,t,coalesce(act,false)) returning * into r;
 return r;
end $$;

create function public.save_settings(p int, w boolean, m text[]) returns void language sql security definer set search_path=public as $$
 update public.profiles set mute_pct=greatest(0,least(100,p)), show_welcome=w, muted=coalesce(m,'{}') where id=auth.uid() $$;

create function public.touch_login() returns timestamptz language plpgsql security definer set search_path=public as $$
declare prev timestamptz;
begin
 select last_login into prev from public.profiles where id=auth.uid();
 update public.profiles set last_login=now() where id=auth.uid();
 return prev;
end $$;

create function public.guest_messages(since timestamptz) returns table(id bigint, username text, body text, is_action boolean, created_at timestamptz)
language sql security definer set search_path=public as $$
 select m.id,m.username,m.body,m.is_action,m.created_at from public.messages m
 where m.created_at >= greatest(since, now() - interval '24 hours') order by m.created_at limit 500 $$;

create function public.send_request(w text, a text, t text) returns void language plpgsql security definer set search_path=public as $$
begin
 if char_length(coalesce(w,'')) not between 1 and 1000 or char_length(coalesce(a,'')) not between 1 and 200 or char_length(coalesce(t,'')) not between 1 and 200 then raise exception 'bad request'; end if;
 insert into public.requests(why,who,contact) values (w,a,t);
end $$;

-- Admin tools (used by admin.html). Wrong passphrase = error after 1 second.
create function public.admin_ok(p text) returns void language plpgsql security definer set search_path=public as $$
begin
 if p is distinct from (select value from public.config where key='admin_pass') then perform pg_sleep(1); raise exception 'wrong passphrase'; end if;
end $$;

create function public.admin_new_invite(p text) returns text language plpgsql security definer set search_path=public as $$
declare a text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; c text := ''; i int;
begin
 perform public.admin_ok(p);
 for i in 1..10 loop c := c || substr(a, 1+floor(random()*32)::int, 1); if i=5 then c := c||'-'; end if; end loop;
 c := c || '-NORMAL';
 insert into public.invites(code) values (c);
 return c;
end $$;

create function public.admin_overview(p text) returns json language plpgsql security definer set search_path=public as $$
begin
 perform public.admin_ok(p);
 return json_build_object(
  'invites',(select coalesce(json_agg(i order by i.created_at desc),'[]'::json) from public.invites i where i.used_at is null and i.created_at > now()-interval '3 days'),
  'requests',(select coalesce(json_agg(r order by r.created_at desc),'[]'::json) from (select * from public.requests order by created_at desc limit 50) r),
  'users',(select coalesce(json_agg(u.username order by u.username),'[]'::json) from public.profiles u),
  'messages',(select coalesce(json_agg(m),'[]'::json) from (select id,username,left(body,80) as body from public.messages order by created_at desc limit 30) m));
end $$;

create function public.admin_delete_message(p text, mid bigint) returns void language plpgsql security definer set search_path=public as $$
begin perform public.admin_ok(p); delete from public.messages where id=mid; end $$;

create function public.admin_ban(p text, n text) returns void language plpgsql security definer set search_path=public as $$
begin perform public.admin_ok(p); delete from auth.users where id=(select id from public.profiles where lower(username)=lower(n)); end $$;

-- Hourly cleanup: messages older than 2 months, invites older than 30 days.
create extension if not exists pg_cron;
select cron.schedule('chatty-cleanup','0 * * * *',$$delete from public.messages where created_at < now()-interval '60 days'; delete from public.invites where created_at < now()-interval '30 days'$$);
