import { createClient } from '@supabase/supabase-js';

export const SUPABASE_URL = 'https://vqbtuzauqchopdlbgylk.supabase.co';
export const SUPABASE_ANON_KEY = 'sb_publishable_3J7GWLlBDikRmzXaDnTFoQ_1oAXwKyM';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
});
