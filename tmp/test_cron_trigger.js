
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
dotenv.config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

async function testTrigger() {
    console.log('Sending unauthorized trigger request to /api/cron/whatsapp-daily...');
    
    try {
        const response = await fetch('http://localhost:3002/api/cron/whatsapp-daily', {
            headers: {
                'X-Attempt-Type': 'simulation-test'
            }
        });
        
        console.log(`Response Status: ${response.status}`);
        const result = await response.json();
        console.log('Response Body:', result);

        if (response.status === 401) {
            console.log('Got 401 as expected. Checking logs in database...');
            
            // Wait a bit for the log to be inserted
            await new Promise(resolve => setTimeout(resolve, 2000));

            const { data: logs, error } = await supabase
                .from('cron_job_logs')
                .select('*')
                .eq('status', 'unauthorized_attempt')
                .order('timestamp', { ascending: false })
                .limit(1);

            if (error) {
                console.error('Error fetching logs:', error.message);
            } else if (logs && logs.length > 0) {
                const log = logs[0];
                console.log('Success! Found unauthorized attempt log:');
                console.log(`ID: ${log.id}`);
                console.log(`Timestamp: ${log.timestamp}`);
                console.log(`Details: ${JSON.stringify(log.details)}`);
            } else {
                console.log('No unauthorized attempt log found in database.');
            }
        } else {
            console.log('Did not get 401. Check if the server is running and logic is correct.');
        }
    } catch (err) {
        console.error('Fetch error:', err.message);
        console.log('Ensure the server is running on http://localhost:3002');
    }
}

testTrigger();
