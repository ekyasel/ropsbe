import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

let supabaseUrl = process.env.SUPABASE_URL;
let supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey || supabaseUrl === 'your_supabase_project_url' || supabaseAnonKey === 'your_supabase_anon_key') {
    console.warn('⚠️  Missing or default Supabase credentials. Auth APIs will not function correctly. Please update .env file.');
    supabaseUrl = 'https://placeholder.supabase.co'; // Placeholder to prevent crash during init
    supabaseAnonKey = 'placeholder-key';
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
