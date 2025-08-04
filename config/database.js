const { createClient } = require('@supabase/supabase-js');
const logger = require('../utils/logger');

let supabase;

const initializeSupabase = () => {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    logger.error('Missing Supabase configuration');
    process.exit(1);
  }

  supabase = createClient(supabaseUrl, supabaseKey, {
    auth: {
      autoRefreshToken: true,
      persistSession: false
    }
  });

  logger.info('✅ Supabase initialized successfully');
};

const getSupabaseClient = () => {
  if (!supabase) {
    throw new Error('Supabase not initialized');
  }
  return supabase;
};

module.exports = {
  initializeSupabase,
  getSupabaseClient
};
