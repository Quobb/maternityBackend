// routes/healthTips.js (Replace existing GET / route)
const { getSupabaseClient } = require('../config/database');
const { getCached, setCached } = require('../config/cache');
const logger = require('../utils/logger');
const { auditLog } = require('../utils/logger');
const axios = require('axios');

const router = require('express').Router();

// Mock AI API call (replace with actual xAI API endpoint)
async function getAIPersonalizedTips(userProfile, pregnancyWeek) {
  try {
    const response = await axios.post(
      process.env.XAI_API_URL || 'https://api.x.ai/v1/recommendations',
      {
        user_profile: userProfile,
        pregnancy_week: pregnancyWeek,
        api_key: process.env.XAI_API_KEY,
      },
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
    return response.data.recommendations;
    
  } catch (error) {
    logger.error('AI API error:', error);
    return null; // Fallback to rule-based logic
  }
}

router.get('/', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    const cacheKey = `health_tips:${req.user.id}:${new Date().toISOString().split('T')[0]}`;

    const cachedTips = await getCached(cacheKey);
    if (cachedTips) {
      return res.json(cachedTips);
    }

    const { data: pregnancy } = await supabase
      .from('pregnancies')
      .select('start_date')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .single();

    if (!pregnancy) {
      return res.status(404).json({ error: 'No active pregnancy found' });
    }

    const { data: profile } = await supabase
      .from('user_profiles')
      .select('medical_conditions, dietary_preferences')
      .eq('user_id', req.user.id)
      .single();

    const { data: wearable } = await supabase
      .from('wearable_data')
      .select('heart_rate, blood_pressure, temperature')
      .eq('user_id', req.user.id)
      .order('timestamp', { ascending: false })
      .limit(1)
      .single();

    const currentWeek = Math.floor((new Date() - new Date(pregnancy.start_date)) / (7 * 24 * 60 * 60 * 1000));
    const input = {
      Age: req.user.age || 25,  // Assume default if not available
      SystolicBP: wearable?.blood_pressure ? parseInt(wearable.blood_pressure.split('/')[0]) : 120,
      DiastolicBP: wearable?.blood_pressure ? parseInt(wearable.blood_pressure.split('/')[1]) : 80,
      BS: profile?.medical_conditions?.includes('diabetes') ? 6.0 : 4.5,  // Simplified assumption
      BodyTemp: wearable?.temperature ? (wearable.temperature * 9 / 5 + 32) : 98.6,  // Convert to Fahrenheit
      HeartRate: wearable?.heart_rate || 80,
    };

    let category;
    try {
      const response = await axios.post(
        process.env.MODEL_API_URL + '/health-tips',
        input,
        { headers: { 'Content-Type': 'application/json' } }
      );
      category = response.data.category;
    } catch (error) {
      logger.error('Model API error:', error);
      category = input.BS > 5.5 ? 'nutrition' :
        (input.HeartRate < 60 || input.HeartRate > 100) ? 'mental_health' : 'exercise';
    }

    const { data: healthTips, error } = await supabase
      .from('health_tips')
      .select('*')
      .eq('category', category)
      .lte('week_start', Math.max(0, currentWeek))
      .gte('week_end', Math.max(0, currentWeek))
      .order('created_at', { ascending: false });

    if (error) {
      logger.error('Get health tips error:', error);
      return res.status(500).json({ error: 'Failed to fetch health tips' });
    }

    const response = {
      currentWeek: Math.max(0, currentWeek),
      healthTips,
      source: category === healthTips[0]?.category ? 'model' : 'rule-based',
    };

    await setCached(cacheKey, response, 24 * 60 * 60);
    auditLog('fetch_health_tips', req.user.id, { week: currentWeek, source: response.source });
    res.json(response);
  } catch (error) {
    logger.error('Get health tips error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get tips by category
router.get('/category/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const supabase = getSupabaseClient();

    const { data: healthTips, error } = await supabase
      .from('health_tips')
      .select('*')
      .eq('category', category)
      .order('week_start', { ascending: true });

    if (error) {
      logger.error('Get health tips by category error:', error);
      return res.status(500).json({ error: 'Failed to fetch health tips' });
    }

    res.json({ healthTips });

  } catch (error) {
    logger.error('Get health tips by category error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// routes/healthTips.js (Modify existing GET / route)
router.get('/', async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancy } = await supabase
      .from('pregnancies')
      .select('start_date')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .single();

    if (!pregnancy) {
      return res.status(404).json({ error: 'No active pregnancy found' });
    }

    const startDate = new Date(pregnancy.start_date);
    const currentWeek = Math.floor((new Date() - startDate) / (7 * 24 * 60 * 60 * 1000));

    // Get user health profile
    const { data: profile } = await supabase
      .from('user_profiles')
      .select('medical_conditions, dietary_preferences')
      .eq('user_id', req.user.id)
      .single();

    let query = supabase
      .from('health_tips')
      .select('*')
      .lte('week_start', Math.max(0, currentWeek))
      .gte('week_end', Math.max(0, currentWeek));

    // Apply basic personalization filters
    if (profile?.medical_conditions?.includes('diabetes')) {
      query = query.or('category.eq.nutrition,category.eq.diabetes_management');
    } else if (profile?.dietary_preferences?.includes('vegetarian')) {
      query = query.or('category.eq.nutrition,category.eq.vegetarian_diet');
    }

    const { data: healthTips, error } = await query.order('created_at', { ascending: false });

    if (error) {
      logger.error('Get health tips error:', error);
      return res.status(500).json({ error: 'Failed to fetch health tips' });
    }

    // Placeholder for AI API integration
    // const personalizedTips = await xaiApi.personalizeTips(healthTips, profile, currentWeek);

    res.json({
      currentWeek: Math.max(0, currentWeek),
      healthTips,
      personalized: profile ? true : false
    });

  } catch (error) {
    logger.error('Get health tips error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
