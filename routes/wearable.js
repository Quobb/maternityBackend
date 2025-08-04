const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');
const Joi = require('joi');
const { getCached, setCached } = require('../config/cache');
const axios = require('axios');

const router = express.Router();



async function predictRisk(userProfile, wearableData) {
  try {
    const response = await axios.post(
      process.env.XAI_API_URL || 'https://api.x.ai/v1/risk-assessment',
      {
        user_profile: userProfile,
        wearable_data: wearableData,
        api_key: process.env.XAI_API_KEY,
      },
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
    return response.data; // Expected: { risk_level: 'low|medium|high', details: {...} }
  } catch (error) {
    logger.error('AI risk prediction error:', error);
    return null; // Fallback to rule-based
  }
}

router.post('/assess-risk', requireRole(['mother']), async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    const cacheKey = `risk_assessment:${req.user.id}:${new Date().toISOString().split('T')[0]}`;

    const cachedAssessment = await getCached(cacheKey);
    if (cachedAssessment) {
      return res.json(cachedAssessment);
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

    const { data: wearable } = await supabase
      .from('wearable_data')
      .select('heart_rate, blood_pressure, temperature, steps')
      .eq('user_id', req.user.id)
      .order('timestamp', { ascending: false })
      .limit(1)
      .single();

    const input = {
      Age: req.user.age || 25,
      SystolicBP: wearable?.blood_pressure ? parseInt(wearable.blood_pressure.split('/')[0]) : 120,
      DiastolicBP: wearable?.blood_pressure ? parseInt(wearable.blood_pressure.split('/')[1]) : 80,
      BS: req.user.medical_conditions?.includes('diabetes') ? 6.0 : 4.5,
      BodyTemp: wearable?.temperature ? (wearable.temperature * 9/5 + 32) : 98.6,
      HeartRate: wearable?.heart_rate || 80,
    };

    let riskLevel;
    try {
      const response = await axios.post(
        process.env.MODEL_API_URL + '/risk-assessment',
        input,
        { headers: { 'Content-Type': 'application/json' } }
      );
      riskLevel = response.data.risk_level;
    } catch (error) {
      logger.error('Model API error:', error);
      riskLevel = 'low';
      if (input.HeartRate > 120 || input.HeartRate < 60 || input.SystolicBP > 140 || input.DiastolicBP > 90 || input.BodyTemp > 100.4) {
        riskLevel = 'high';
      } else if (input.HeartRate > 100 || input.SystolicBP > 120 || input.BS > 5.5) {
        riskLevel = 'medium';
      }
    }

    const assessmentId = uuidv4();
    const { error: insertError } = await supabase
      .from('risk_assessments')
      .insert([
        {
          id: assessmentId,
          user_id: req.user.id,
          risk_level: riskLevel,
          details: { model_input: input },
          created_at: new Date().toISOString(),
        },
      ]);

    if (insertError) {
      logger.error('Store risk assessment error:', insertError);
      return res.status(500).json({ error: 'Failed to store risk assessment' });
    }

    if (riskLevel === 'high') {
      const alertId = uuidv4();
      await supabase
        .from('emergency_alerts')
        .insert([
          {
            id: alertId,
            user_id: req.user.id,
            type: 'high_risk',
            message: `High risk detected: ${JSON.stringify(input)}`,
            triggered_at: new Date().toISOString(),
            resolved: false,
          },
        ]);
    }

    const response = {
      riskAssessment: {
        id: assessmentId,
        risk_level: riskLevel,
        details: { model_input: input },
        created_at: new Date().toISOString(),
      },
      source: riskLevel === (await axios.post(process.env.MODEL_API_URL + '/risk-assessment', input).catch(() => ({}))).data?.risk_level ? 'model' : 'rule-based',
    };

    await setCached(cacheKey, response, 24 * 60 * 60);
    auditLog('risk_assessment', req.user.id, { risk_level: riskLevel, source: response.source });
    res.json(response);
  } catch (error) {
    logger.error('Risk assessment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Sync wearable data
router.post('/sync', requireRole(['mother']), async (req, res) => {
  try {
    const { heart_rate, blood_pressure, temperature, steps, timestamp } = req.body;
    const supabase = getSupabaseClient();

    const wearableDataId = uuidv4();
    const { data: wearableData, error } = await supabase
      .from('wearable_data')
      .insert([{
        id: wearableDataId,
        user_id: req.user.id,
        timestamp: timestamp || new Date().toISOString(),
        heart_rate,
        blood_pressure,
        temperature,
        steps
      }])
      .select()
      .single();

    if (error) {
      logger.error('Wearable data sync error:', error);
      return res.status(500).json({ error: 'Failed to sync wearable data' });
    }

    // Check for emergency conditions
    await checkEmergencyConditions(req.user.id, {
      heart_rate,
      blood_pressure,
      temperature
    });

    res.status(201).json({
      message: 'Wearable data synced successfully',
      data: wearableData
    });

  } catch (error) {
    logger.error('Sync wearable data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get wearable data
router.get('/data', async (req, res) => {
  try {
    const { days = 7, type } = req.query;
    const supabase = getSupabaseClient();

    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - parseInt(days));

    let selectFields = '*';
    if (type) {
      const validTypes = ['heart_rate', 'blood_pressure', 'temperature', 'steps'];
      if (validTypes.includes(type)) {
        selectFields = `id, user_id, timestamp, ${type}`;
      }
    }

    const { data: wearableData, error } = await supabase
      .from('wearable_data')
      .select(selectFields)
      .eq('user_id', req.user.id)
      .gte('timestamp', fromDate.toISOString())
      .order('timestamp', { ascending: false });

    if (error) {
      logger.error('Get wearable data error:', error);
      return res.status(500).json({ error: 'Failed to fetch wearable data' });
    }

    res.json({
      data: wearableData,
      summary: calculateDataSummary(wearableData, type)
    });

  } catch (error) {
    logger.error('Get wearable data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to check emergency conditions
async function checkEmergencyConditions(userId, vitals) {
  const supabase = getSupabaseClient();
  const alerts = [];

  // Check heart rate
  if (vitals.heart_rate) {
    if (vitals.heart_rate > 120 || vitals.heart_rate < 50) {
      alerts.push({
        type: vitals.heart_rate > 120 ? 'high_hr' : 'low_hr',
        message: `Heart rate ${vitals.heart_rate} BPM is ${vitals.heart_rate > 120 ? 'high' : 'low'}`
      });
    }
  }

  // Check blood pressure
  if (vitals.blood_pressure) {
    const [systolic, diastolic] = vitals.blood_pressure.split('/').map(Number);
    if (systolic > 140 || diastolic > 90) {
      alerts.push({
        type: 'high_bp',
        message: `Blood pressure ${vitals.blood_pressure} is elevated`
      });
    }
  }

  // Check temperature
  if (vitals.temperature) {
    if (vitals.temperature > 38.0) {
      alerts.push({
        type: 'high_temp',
        message: `Temperature ${vitals.temperature}°C is elevated`
      });
    }
  }

  // Create emergency alerts
  for (const alert of alerts) {
    const alertId = uuidv4();
    await supabase
      .from('emergency_alerts')
      .insert([{
        id: alertId,
        user_id: userId,
        triggered_at: new Date().toISOString(),
        type: alert.type,
        resolved: false
      }]);

    // Here you would typically send notifications (email, SMS, push)
    logger.warn(`Emergency alert for user ${userId}: ${alert.message}`);
  }
}

// Helper function to calculate data summary
function calculateDataSummary(data, type) {
  if (!data || data.length === 0) return null;

  const summary = {};

  if (!type || type === 'heart_rate') {
    const heartRates = data.filter(d => d.heart_rate).map(d => d.heart_rate);
    if (heartRates.length > 0) {
      summary.heart_rate = {
        average: Math.round(heartRates.reduce((a, b) => a + b, 0) / heartRates.length),
        min: Math.min(...heartRates),
        max: Math.max(...heartRates)
      };
    }
  }

  if (!type || type === 'steps') {
    const steps = data.filter(d => d.steps).map(d => d.steps);
    if (steps.length > 0) {
      summary.steps = {
        total: steps.reduce((a, b) => a + b, 0),
        average: Math.round(steps.reduce((a, b) => a + b, 0) / steps.length),
        max: Math.max(...steps)
      };
    }
  }

  if (!type || type === 'temperature') {
    const temperatures = data.filter(d => d.temperature).map(d => d.temperature);
    if (temperatures.length > 0) {
      summary.temperature = {
        average: Math.round(temperatures.reduce((a, b) => a + b, 0) / temperatures.length * 10) / 10,
        min: Math.min(...temperatures),
        max: Math.max(...temperatures)
      };
    }
  }

  return summary;
}


// routes/wearable.js (Modify POST /sync route)

const wearableDataSchema = Joi.object({
  heart_rate: Joi.number().min(30).max(200).optional(),
  blood_pressure: Joi.string().pattern(/^\d{2,3}\/\d{2,3}$/).optional(),
  temperature: Joi.number().min(35).max(42).optional(),
  steps: Joi.number().integer().min(0).optional(),
  timestamp: Joi.date().iso().optional(),
}).min(1);

router.post('/sync', requireRole(['mother']), async (req, res) => {
  try {
    const { error: validationError } = wearableDataSchema.validate(req.body);
    if (validationError) {
      return res.status(400).json({ error: 'Invalid wearable data', details: validationError.details });
    }

    const { heart_rate, blood_pressure, temperature, steps, timestamp } = req.body;
    const supabase = getSupabaseClient();

    const wearableDataId = uuidv4();
    const { data: wearableData, error } = await supabase
      .from('wearable_data')
      .insert([{
        id: wearableDataId,
        user_id: req.user.id,
        timestamp: timestamp || new Date().toISOString(),
        heart_rate,
        blood_pressure,
        temperature,
        steps
      }])
      .select()
      .single();

    if (error) {
      logger.error('Wearable data sync error:', error);
      return res.status(500).json({ error: 'Failed to sync wearable data' });
    }

    await checkEmergencyConditions(req.user.id, {
      heart_rate,
      blood_pressure,
      temperature
    });

    res.status(201).json({
      message: 'Wearable data synced successfully',
      data: wearableData
    });

  } catch (error) {
    logger.error('Sync wearable data error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
