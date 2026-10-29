import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
};
const respond = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), { status, headers: cors });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
  if (req.method !== 'POST') return respond(405, { error: 'Method tidak diizinkan.' });
  try {
    const url = Deno.env.get('SUPABASE_URL');
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY');
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
    if (!url || !anonKey || !serviceKey) return respond(500, { error: 'Konfigurasi server belum lengkap.' });
    const authorization = req.headers.get('authorization') || '';
    if (!authorization.startsWith('Bearer ')) return respond(401, { error: 'Login Admin diperlukan.' });
    const token = authorization.slice(7);
    const authClient = createClient(url, anonKey, { auth: { persistSession: false } });
    const { data: caller, error: callerError } = await authClient.auth.getUser(token);
    if (callerError || !caller.user) return respond(401, { error: 'Sesi Admin tidak valid.' });
    if (caller.user.app_metadata?.smart_seating_role !== 'admin') return respond(403, { error: 'Hanya Admin yang diizinkan.' });

    const { email, password } = await req.json();
    if (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || typeof password !== 'string' || password.length < 8 || password.length > 128)
      return respond(400, { error: 'Email atau password tidak valid (8–128 karakter).' });
    const normalizedEmail = email.trim().toLowerCase();
    const admin = createClient(url, serviceKey, { auth: { persistSession: false } });
    let target: { id: string; app_metadata?: Record<string, unknown> } | undefined;
    for (let page = 1; page <= 100; page++) {
      const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 100 });
      if (error) return respond(500, { error: 'Gagal memeriksa akun Staff.' });
      target = data.users.find((u) => u.email?.toLowerCase() === normalizedEmail);
      if (target || data.users.length < 100) break;
    }
    if (!target) return respond(404, { error: 'Email Staff tidak ditemukan.' });
    if (target.id === caller.user.id || target.app_metadata?.smart_seating_role !== 'staff')
      return respond(403, { error: 'Email tersebut bukan akun Staff. Password Admin tidak dapat diubah di sini.' });
    const { error } = await admin.auth.admin.updateUserById(target.id, { password });
    if (error) return respond(500, { error: 'Gagal menyimpan password Staff.' });
    return respond(200, { ok: true });
  } catch {
    return respond(500, { error: 'Permintaan gagal diproses.' });
  }
});
