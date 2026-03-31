import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config();

let supabaseUrl = process.env.SUPABASE_URL;
let supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey || supabaseUrl === 'your_supabase_project_url' || supabaseAnonKey === 'your_supabase_anon_key') {
    console.warn('⚠️  Missing or default Supabase credentials. Auth APIs will not function correctly. Please update .env file.');
    supabaseUrl = 'https://gjafqwiutgytxjvusnfa.supabase.co'; // Placeholder to prevent crash during init
    supabaseAnonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImdqYWZxd2l1dGd5dHhqdnVzbmZhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzEyNjQ0NDMsImV4cCI6MjA4Njg0MDQ0M30.AgwCGvKOi7zgwksasJNZ-rs6AodMYrNhfSLJHx6qL1g';
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);
