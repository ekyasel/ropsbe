
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
dotenv.config();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const { data: logs } = await supabase.from('cron_job_logs')
    .select('timestamp, status, summary')
    .order('timestamp', { ascending: false })
    .limit(20);
if (logs) {
    logs.forEach(l => console.log(`${l.timestamp} | ${l.status} | ${l.summary}`));
}
process.exit(0);
