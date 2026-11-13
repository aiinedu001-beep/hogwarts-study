-- 霍格華茲私人刷題網站：Supabase SQL 設定
-- 在 Supabase Dashboard → SQL Editor → New query 貼上並 Run。

create extension if not exists pgcrypto;

create table if not exists public.hp_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.hp_courses (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  tag text,
  description text,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.hp_questions (
  id uuid primary key default gen_random_uuid(),
  course_id uuid not null references public.hp_courses(id) on delete cascade,
  question_text text not null,
  option_a text,
  option_b text,
  option_c text,
  option_d text,
  answer text not null check (upper(answer) in ('A','B','C','D')),
  explanation text,
  sort_order integer not null default 0,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.hp_attempts (
  id uuid primary key default gen_random_uuid(),
  question_id uuid not null references public.hp_questions(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  selected_answer text not null,
  is_correct boolean not null,
  created_at timestamptz not null default now(),
  unique(question_id,user_id)
);

create or replace function public.hp_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists(select 1 from public.hp_admins where user_id = auth.uid());
$$;

alter table public.hp_admins enable row level security;
alter table public.hp_courses enable row level security;
alter table public.hp_questions enable row level security;
alter table public.hp_attempts enable row level security;

drop policy if exists "admins can read own admin row" on public.hp_admins;
create policy "admins can read own admin row" on public.hp_admins
for select to authenticated using (user_id = auth.uid());

drop policy if exists "authenticated read courses" on public.hp_courses;
create policy "authenticated read courses" on public.hp_courses
for select to authenticated using (true);
drop policy if exists "admins manage courses" on public.hp_courses;
create policy "admins manage courses" on public.hp_courses
for all to authenticated using (public.hp_is_admin()) with check (public.hp_is_admin());

drop policy if exists "authenticated read questions" on public.hp_questions;
create policy "authenticated read questions" on public.hp_questions
for select to authenticated using (true);
drop policy if exists "admins manage questions" on public.hp_questions;
create policy "admins manage questions" on public.hp_questions
for all to authenticated using (public.hp_is_admin()) with check (public.hp_is_admin());

drop policy if exists "users read own attempts" on public.hp_attempts;
create policy "users read own attempts" on public.hp_attempts
for select to authenticated using (user_id = auth.uid());
drop policy if exists "users insert own attempts" on public.hp_attempts;
create policy "users insert own attempts" on public.hp_attempts
for insert to authenticated with check (
  user_id = auth.uid()
  and exists(select 1 from public.hp_questions q where q.id = question_id)
);
-- 不允許學生自行修改或刪除已提交的作答紀錄。

insert into public.hp_courses(name,tag,description,sort_order)
select v.name,v.tag,v.description,v.sort_order
from (values
 ('古代文字學','國文','閱讀、文意理解與古典文本',1),
 ('魔法數理學','數學 A','學測數學觀念與計算練習',2),
 ('魔法語言學','英文','字彙、文法與閱讀測驗',3),
 ('魔法生物學','自然','自然科學概念與素養題',4),
 ('魔法史學','社會','歷史、地理與公民素養',5),
 ('魔藥學','跨科','跨領域整合題型',6),
 ('符咒學','國文','語文表達與閱讀技巧',7)
) as v(name,tag,description,sort_order)
where not exists(select 1 from public.hp_courses c where c.name=v.name);


-- 避免一般登入者直接讀取答案欄位；題目透過 RPC 批改並回傳答案。
revoke select on table public.hp_questions from anon, authenticated;
grant select(id,course_id,question_text,option_a,option_b,option_c,option_d,explanation,sort_order,created_at)
on table public.hp_questions to authenticated;

create or replace function public.hp_submit_answer(p_question_id uuid, p_selected_answer text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_answer text;
  v_explanation text;
  v_correct boolean;
begin
  if auth.uid() is null then
    raise exception '請先登入';
  end if;

  select answer, explanation into v_answer, v_explanation
  from public.hp_questions
  where id = p_question_id;

  if not found then
    raise exception '找不到這道題目';
  end if;

  v_correct := upper(trim(p_selected_answer)) = upper(trim(v_answer));

  insert into public.hp_attempts(question_id,user_id,selected_answer,is_correct)
  values(p_question_id,auth.uid(),upper(trim(p_selected_answer)),v_correct);

  return jsonb_build_object(
    'is_correct',v_correct,
    'correct_answer',v_answer,
    'explanation',coalesce(v_explanation,'')
  );
end;
$$;

revoke all on function public.hp_submit_answer(uuid,text) from public;
grant execute on function public.hp_submit_answer(uuid,text) to authenticated;
