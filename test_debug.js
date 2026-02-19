import { supabase } from './supabase.js';
import dotenv from 'dotenv';
dotenv.config();

async function testQuery() {
    try {
        console.log("Testing query...");
        const { data, error, count } = await supabase
            .from('pendaftaran_operasi')
            .select('*')
            .limit(1);

        if (error) {
            console.error("Supabase Error:", error);
        } else {
            console.log("Success! Data:", JSON.stringify(data, null, 2));
        }
    } catch (err) {
        console.error("Caught Error:", err);
    }
}

testQuery();
