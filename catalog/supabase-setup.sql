-- كتالوج المنتجات | Supabase setup
-- شغّل هذا الملف مرة واحدة داخل Supabase SQL Editor.
-- بعد إنشاء أول مستخدم من Authentication > Users، أضف ملف المسؤول
-- باستبدال UUID أدناه بمعرّف المستخدم الذي أنشأته:
-- insert into public.catalog_profiles(user_id, display_name, role, is_active)
-- values ('PUT-AUTH-USER-UUID-HERE', 'المسؤول', 'admin', true);

create table if not exists public.catalog_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  role text not null default 'rep' check (role in ('admin','rep')),
  allowed_price text check (allowed_price in ('beautiful','wholesale','market') or allowed_price is null),
  allowed_categories text[] not null default '{}',
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.catalog_products (
  id uuid primary key default gen_random_uuid(),
  barcode text unique,
  name text not null,
  category text not null default '',
  pack text not null default '',
  weight text not null default '',
  image_path text,
  active boolean not null default true,
  sort_order integer not null default 0,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

-- السعر منفصل عن بيانات المنتج حتى لا يستطيع المندوب قراءة أسعار غير مخصصة له.
create table if not exists public.catalog_prices (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.catalog_products(id) on delete cascade,
  price_type text not null check (price_type in ('beautiful','wholesale','market')),
  amount numeric(14,2),
  offer_text text not null default '',
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null,
  unique(product_id, price_type)
);

create index if not exists catalog_products_category_idx on public.catalog_products(category);
create index if not exists catalog_products_barcode_idx on public.catalog_products(barcode);
create index if not exists catalog_prices_product_idx on public.catalog_prices(product_id);

create or replace function public.catalog_is_admin()
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.catalog_profiles p
    where p.user_id = (select auth.uid())
      and p.role = 'admin'
      and p.is_active = true
  );
$$;

create or replace function public.catalog_can_view_category(p_category text)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.catalog_profiles p
    where p.user_id = (select auth.uid())
      and p.is_active = true
      and (
        p.role = 'admin'
        or cardinality(p.allowed_categories) = 0
        or p_category = any(p.allowed_categories)
      )
  );
$$;

create or replace function public.catalog_can_view_price(p_product_id uuid, p_price_type text)
returns boolean
language sql stable security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.catalog_profiles u
    join public.catalog_products pr on pr.id = p_product_id
    where u.user_id = (select auth.uid())
      and u.is_active = true
      and pr.active = true
      and (
        u.role = 'admin'
        or (
          u.allowed_price = p_price_type
          and (cardinality(u.allowed_categories) = 0 or pr.category = any(u.allowed_categories))
        )
      )
  );
$$;

alter table public.catalog_profiles enable row level security;
alter table public.catalog_products enable row level security;
alter table public.catalog_prices enable row level security;

drop policy if exists "profile read self or admin" on public.catalog_profiles;
create policy "profile read self or admin" on public.catalog_profiles
for select to authenticated
using (user_id = (select auth.uid()) or public.catalog_is_admin());

drop policy if exists "admin manage profiles" on public.catalog_profiles;
create policy "admin manage profiles" on public.catalog_profiles
for all to authenticated
using (public.catalog_is_admin())
with check (public.catalog_is_admin());

drop policy if exists "read allowed products" on public.catalog_products;
create policy "read allowed products" on public.catalog_products
for select to authenticated
using (active = true and public.catalog_can_view_category(category));

drop policy if exists "admin manage products" on public.catalog_products;
create policy "admin manage products" on public.catalog_products
for all to authenticated
using (public.catalog_is_admin())
with check (public.catalog_is_admin());

drop policy if exists "read assigned prices only" on public.catalog_prices;
create policy "read assigned prices only" on public.catalog_prices
for select to authenticated
using (public.catalog_can_view_price(product_id, price_type));

drop policy if exists "admin manage prices" on public.catalog_prices;
create policy "admin manage prices" on public.catalog_prices
for all to authenticated
using (public.catalog_is_admin())
with check (public.catalog_is_admin());

-- مخزن صور خاص؛ لا يمكن تنزيل صورة مادة خارج التصنيفات المسموحة للمستخدم.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('catalog-images', 'catalog-images', false, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public = false, file_size_limit = 5242880,
  allowed_mime_types = array['image/jpeg','image/png','image/webp'];

drop policy if exists "read allowed catalog images" on storage.objects;
create policy "read allowed catalog images" on storage.objects
for select to authenticated
using (
  bucket_id = 'catalog-images'
  and exists (
    select 1 from public.catalog_products p
    where p.image_path = name
      and p.active = true
      and public.catalog_can_view_category(p.category)
  )
);

-- صلاحيات الصور: تحقق مباشر من ملف المسؤول لتفادي رفض الرفع بسبب سياسة التخزين.
drop policy if exists "admin upload catalog images" on storage.objects;
create policy "admin upload catalog images" on storage.objects
for insert to authenticated
with check (
  bucket_id = 'catalog-images'
  and exists (
    select 1 from public.catalog_profiles p
    where p.user_id = (select auth.uid())
      and p.role = 'admin'
      and p.is_active = true
  )
);

drop policy if exists "admin update catalog images" on storage.objects;
create policy "admin update catalog images" on storage.objects
for update to authenticated
using (
  bucket_id = 'catalog-images'
  and exists (
    select 1 from public.catalog_profiles p
    where p.user_id = (select auth.uid())
      and p.role = 'admin'
      and p.is_active = true
  )
)
with check (
  bucket_id = 'catalog-images'
  and exists (
    select 1 from public.catalog_profiles p
    where p.user_id = (select auth.uid())
      and p.role = 'admin'
      and p.is_active = true
  )
);

drop policy if exists "admin delete catalog images" on storage.objects;
create policy "admin delete catalog images" on storage.objects
for delete to authenticated
using (
  bucket_id = 'catalog-images'
  and exists (
    select 1 from public.catalog_profiles p
    where p.user_id = (select auth.uid())
      and p.role = 'admin'
      and p.is_active = true
  )
);

grant usage on schema public to authenticated;
grant select, insert, update, delete on public.catalog_profiles to authenticated;
grant select, insert, update, delete on public.catalog_products to authenticated;
grant select, insert, update, delete on public.catalog_prices to authenticated;
grant execute on function public.catalog_is_admin() to authenticated;
grant execute on function public.catalog_can_view_category(text) to authenticated;
grant execute on function public.catalog_can_view_price(uuid, text) to authenticated;

-- ملاحظة: لا تمنح anon صلاحيات على جداول الكتالوج.
