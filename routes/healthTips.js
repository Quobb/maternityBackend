// routes/healthTips.js - Groq Integration Version
const express = require('express');
const { getCached, setCached, deleteCached } = require('../config/cache');
const { getSupabaseClient } = require('../config/database');
const logger = require('../utils/logger');
const Groq = require("groq-sdk");

// Fix: Properly import auditLog - check if it's a separate export or part of logger
const auditLog = logger.auditLog || ((action, userId, data) => {
  logger.info(`Audit: ${action}`, { userId, ...data });
});

const router = express.Router();

// Initialize Groq client
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// Configuration
const CACHE_DURATION = parseInt(process.env.CACHE_DURATION) || 3600;
const DATABASE_FALLBACK_ENABLED = process.env.DATABASE_FALLBACK_ENABLED !== 'false';

// Helper function to safely calculate gestational week
function calculateGestationalWeek(startDate) {
  try {
    if (!startDate) return 0;
    
    const start = new Date(startDate);
    const current = new Date();
    
    // Validate dates
    if (isNaN(start.getTime())) {
      logger.warn('Invalid start date provided:', startDate);
      return 0;
    }
    
    const diffTime = current - start;
    const diffWeeks = Math.floor(diffTime / (7 * 24 * 60 * 60 * 1000));
    
    // Ensure reasonable gestational week (0-42)
    return Math.max(0, Math.min(42, diffWeeks));
  } catch (error) {
    logger.error('Error calculating gestational week:', error);
    return 0;
  }
}

// Helper function to safely parse numeric values
function safeParseInt(value, defaultValue = 0) {
  const parsed = parseInt(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

function safeParseFloat(value, defaultValue = 0.0) {
  const parsed = parseFloat(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

// Helper function to get user's health data with better error handling
async function getUserHealthData(userId, supabase) {
  try {
    logger.info(`Fetching health data for user ${userId}`);

    // Get pregnancy information
    const { data: pregnancy, error: pregnancyError } = await supabase
      .from('pregnancies')
      .select('start_date, due_date, age_at_conception')
      .eq('user_id', userId)
      .eq('status', 'active')
      .single();

    if (pregnancyError && pregnancyError.code !== 'PGRST116') {
      logger.warn(`Pregnancy query error for user ${userId}:`, pregnancyError);
    }

    if (!pregnancy) {
      logger.warn(`No active pregnancy found for user ${userId}, using defaults`);
      
      // For production, you might want to throw an error here instead
      if (process.env.NODE_ENV === 'production') {
        throw new Error('No active pregnancy found');
      }
      
      // Create default pregnancy data for demo/testing purposes
      const defaultPregnancy = {
        start_date: new Date(Date.now() - (12 * 7 * 24 * 60 * 60 * 1000)).toISOString(),
        due_date: new Date(Date.now() + (28 * 7 * 24 * 60 * 60 * 1000)).toISOString(),
        age_at_conception: 28
      };
      
      logger.info('Using default pregnancy data for development/testing');
      return {
        pregnancy: defaultPregnancy,
        profile: { age: 28, bmi: 24, medical_conditions: [], previous_pregnancies: 0 },
        wearable: null,
        weightData: null,
        gestationalWeek: 12
      };
    }

    // Calculate gestational week safely
    const gestationalWeek = calculateGestationalWeek(pregnancy.start_date);

    // Get user profile with error handling
    const { data: profile, error: profileError } = await supabase
      .from('users_profile')
      .select('age, bmi, medical_conditions, previous_pregnancies')
      .eq('user_id', userId)
      .single();

    if (profileError && profileError.code !== 'PGRST116') {
      logger.warn(`Profile query error for user ${userId}:`, profileError);
    }

    // Get latest wearable/health data
    const { data: wearable, error: wearableError } = await supabase
      .from('wearable_data')
      .select('heart_rate, blood_pressure, temperature, blood_sugar')
      .eq('user_id', userId)
      .order('timestamp', { ascending: false })
      .limit(1)
      .single();

    if (wearableError && wearableError.code !== 'PGRST116') {
      logger.warn(`Wearable data query error for user ${userId}:`, wearableError);
    }

    // Get weight tracking data
    const { data: weightData, error: weightError } = await supabase
      .from('users_profile')
      .select('weight')
      .eq('user_id', userId)
      .limit(1)
      .single();

    if (weightError && weightError.code !== 'PGRST116') {
      logger.warn(`Weight data query error for user ${userId}:`, weightError);
    }

    logger.info(`Health data fetched for user ${userId}:`, {
      hasPregnancy: !!pregnancy,
      hasProfile: !!profile,
      hasWearable: !!wearable,
      hasWeightData: !!weightData,
      gestationalWeek
    });

    return {
      pregnancy,
      profile,
      wearable,
      weightData,
      gestationalWeek
    };

  } catch (error) {
    logger.error('Error fetching user health data:', error);
    throw error;
  }
}

// Enhanced function to fetch health tips from database with better fallbacks
async function fetchHealthTipsFromDatabase(supabase, category, gestationalWeek, userId) {
  try {
    // Ensure gestationalWeek is a valid number
    const safeGestationalWeek = safeParseInt(gestationalWeek, 0);
    
    logger.info(`Fetching health tips from database:`, { 
      category, 
      gestationalWeek: safeGestationalWeek, 
      userId 
    });

    // First try: exact week match
    let { data: healthTips, error } = await supabase
      .from('health_tips')
      .select('*')
      .eq('category', category)
      .lte('week_start', safeGestationalWeek)
      .gte('week_end', safeGestationalWeek)
      .order('created_at', { ascending: false })
      .limit(10);

    if (error) {
      logger.error('Database query error (exact match):', error);
      throw error;
    }

    // If no tips found for exact week, try broader range
    if (!healthTips || healthTips.length === 0) {
      logger.info(`No tips found for exact week ${safeGestationalWeek}, trying broader range`);
      
      const { data: broadTips, error: broadError } = await supabase
        .from('health_tips')
        .select('*')
        .eq('category', category)
        .order('created_at', { ascending: false })
        .limit(15);

      if (broadError) {
        logger.error('Database query error (broad search):', broadError);
      } else {
        healthTips = broadTips;
      }
    }

    // If still no tips for this category, try general category
    if (!healthTips || healthTips.length === 0) {
      logger.info(`No tips found for category ${category}, trying general category`);
      
      const { data: generalTips, error: generalError } = await supabase
        .from('health_tips')
        .select('*')
        .eq('category', 'general')
        .order('created_at', { ascending: false })
        .limit(10);

      if (generalError) {
        logger.error('Database query error (general category):', generalError);
      } else {
        healthTips = generalTips;
      }
    }

    // If STILL no tips, get any tips available
    if (!healthTips || healthTips.length === 0) {
      logger.info('No category-specific tips found, fetching any available tips');
      
      const { data: anyTips, error: anyError } = await supabase
        .from('health_tips')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(5);

      if (anyError) {
        logger.error('Database query error (any tips):', anyError);
      } else {
        healthTips = anyTips;
      }
    }

    logger.info(`Database tips fetched:`, {
      category,
      gestationalWeek: safeGestationalWeek,
      tipsFound: (healthTips || []).length,
      userId
    });

    return healthTips || [];

  } catch (error) {
    logger.error('Error fetching health tips from database:', error);
    return [];
  }
}

// Helper function to create default health tips when database is empty
function createDefaultHealthTips(category, gestationalWeek) {
  const defaultTips = {
    general: [
      {
        id: 'default-1',
        title: 'Stay Hydrated',
        content: 'Drink at least 8-10 glasses of water daily to support your pregnancy.',
        category: 'general',
        week_start: 0,
        week_end: 42
      },
      {
        id: 'default-2',
        title: 'Get Regular Prenatal Checkups',
        content: 'Regular prenatal visits help monitor your baby\'s development and your health.',
        category: 'general',
        week_start: 0,
        week_end: 42
      },
      {
        id: 'default-3',
        title: 'Take Prenatal Vitamins',
        content: 'Ensure you\'re taking prenatal vitamins with folic acid as recommended by your healthcare provider.',
        category: 'general',
        week_start: 0,
        week_end: 42
      }
    ],
    nutrition: [
      {
        id: 'nutrition-1',
        title: 'Eat Folate-Rich Foods',
        content: 'Include leafy greens, citrus fruits, and fortified grains in your diet for healthy fetal development.',
        category: 'nutrition',
        week_start: 0,
        week_end: 42
      },
      {
        id: 'nutrition-2',
        title: 'Choose Whole Grains',
        content: 'Opt for whole grain breads, cereals, and pasta for sustained energy and fiber.',
        category: 'nutrition',
        week_start: 0,
        week_end: 42
      }
    ],
    exercise: [
      {
        id: 'exercise-1',
        title: 'Gentle Walking',
        content: 'Take a 20-30 minute walk daily to maintain fitness and improve circulation.',
        category: 'exercise',
        week_start: 0,
        week_end: 42
      },
      {
        id: 'exercise-2',
        title: 'Prenatal Yoga',
        content: 'Consider prenatal yoga classes to improve flexibility and reduce stress.',
        category: 'exercise',
        week_start: 0,
        week_end: 42
      }
    ],
    mental_health: [
      {
        id: 'mental-1',
        title: 'Practice Relaxation',
        content: 'Try deep breathing exercises or meditation to manage stress and anxiety.',
        category: 'mental_health',
        week_start: 0,
        week_end: 42
      },
      {
        id: 'mental-2',
        title: 'Connect with Support',
        content: 'Stay connected with family, friends, or pregnancy support groups.',
        category: 'mental_health',
        week_start: 0,
        week_end: 42
      }
    ]
  };

  return defaultTips[category] || defaultTips.general;
}

// Helper function to prepare maternal health input
function prepareMaternalHealthInput(healthData) {
  const { pregnancy, profile, wearable, weightData, gestationalWeek } = healthData;
  
  // Parse blood pressure if available
  let systolicBP = 120, diastolicBP = 80;
  if (wearable?.blood_pressure) {
    const bpParts = wearable.blood_pressure.split('/');
    if (bpParts.length === 2) {
      systolicBP = safeParseInt(bpParts[0], 120);
      diastolicBP = safeParseInt(bpParts[1], 80);
    }
  }

  // Convert temperature to Fahrenheit if needed
  let bodyTemp = 98.6;
  if (wearable?.temperature) {
    bodyTemp = safeParseFloat(wearable.temperature, 98.6);
    // Assume Celsius if temperature is below 50, convert to Fahrenheit
    if (bodyTemp < 50) {
      bodyTemp = (bodyTemp * 9/5) + 32;
    }
  }

  // Estimate blood sugar based on conditions
  let bloodSugar = 95.0;
  if (wearable?.blood_sugar) {
    bloodSugar = safeParseFloat(wearable.blood_sugar, 95.0);
  } else if (profile?.medical_conditions?.includes('diabetes') || 
             profile?.medical_conditions?.includes('gestational_diabetes')) {
    bloodSugar = 130.0;
  }

  // Ensure gestational week is valid
  const safeGestationalWeek = safeParseInt(gestationalWeek, 12);

  return {
    age: safeParseInt(profile?.age || pregnancy?.age_at_conception, 28),
    gestational_week: Math.min(42, Math.max(12, safeGestationalWeek + 12)),
    systolic_bp: Math.max(80, Math.min(200, systolicBP)),
    diastolic_bp: Math.max(50, Math.min(120, diastolicBP)),
    blood_sugar: Math.max(60, Math.min(250, bloodSugar)),
    body_temp: Math.max(96, Math.min(104, bodyTemp)),
    heart_rate: Math.max(50, Math.min(150, safeParseInt(wearable?.heart_rate, 85))),
    bmi: Math.max(15, Math.min(50, safeParseFloat(profile?.bmi, 24))),
    previous_pregnancies: Math.max(0, Math.min(10, safeParseInt(profile?.previous_pregnancies, 0))),
    weight_gain: Math.max(-20, Math.min(80, safeParseFloat(weightData?.weight_gain, 25)))
  };
}

// Groq-based AI Health Recommendations
async function getGroqHealthRecommendations(healthData) {
  try {
    const prompt = `You are a maternal health AI assistant. Based on the following health data, provide personalized health recommendations in JSON format.

Health Data:
- Age: ${healthData.age} years
- Gestational week: ${healthData.gestational_week}
- Blood pressure: ${healthData.systolic_bp}/${healthData.diastolic_bp} mmHg
- Heart rate: ${healthData.heart_rate} bpm
- BMI: ${healthData.bmi}
- Blood sugar: ${healthData.blood_sugar} mg/dL
- Body temperature: ${healthData.body_temp}°F
- Previous pregnancies: ${healthData.previous_pregnancies}
- Weight gain: ${healthData.weight_gain} lbs

Please respond with a JSON object containing:
{
  "category": "one of: General Focus, Nutrition Focus, Exercise Focus, Wellness Focus",
  "confidence": 0.8,
  "tips": ["tip1", "tip2", "tip3"],
  "focus_area": "brief description of main focus area",
  "source": "groq-ai"
}

Focus on practical, safe recommendations appropriate for pregnancy. Always include disclaimer about consulting healthcare provider.`;

    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are a maternal health AI assistant. Provide safe, evidence-based pregnancy health recommendations. Always remind users to consult their healthcare provider. Respond only in valid JSON format."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      model: "llama3-8b-8192",
      temperature: 0.3,
      max_tokens: 500
    });

    const responseText = completion.choices[0]?.message?.content;
    if (!responseText) {
      throw new Error('No response from Groq');
    }

    // Clean and parse JSON response
    const cleanedResponse = responseText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const recommendations = JSON.parse(cleanedResponse);

    logger.info('Groq health recommendations generated successfully');
    return recommendations;

  } catch (error) {
    logger.error('Error getting Groq health recommendations:', error);
    return null;
  }
}

// Groq-based Risk Assessment
async function getGroqRiskAssessment(healthData) {
  try {
    const prompt = `You are a maternal health AI assistant. Analyze the following health data and provide a risk assessment in JSON format.

Health Data:
- Age: ${healthData.age} years
- Gestational week: ${healthData.gestational_week}
- Blood pressure: ${healthData.systolic_bp}/${healthData.diastolic_bp} mmHg
- Heart rate: ${healthData.heart_rate} bpm
- BMI: ${healthData.bmi}
- Blood sugar: ${healthData.blood_sugar} mg/dL
- Body temperature: ${healthData.body_temp}°F
- Previous pregnancies: ${healthData.previous_pregnancies}
- Weight gain: ${healthData.weight_gain} lbs

Please respond with a JSON object containing:
{
  "risk_level": "Low Risk, Medium Risk, or High Risk",
  "confidence": 0.8,
  "recommendation": "specific recommendation based on risk level",
  "risk_factors": ["factor1", "factor2"],
  "source": "groq-ai"
}

Base assessment on standard obstetric guidelines. Always recommend consulting healthcare provider for concerning values.`;

    const completion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are a maternal health AI assistant. Provide evidence-based pregnancy risk assessments. Always emphasize consulting healthcare providers. Respond only in valid JSON format."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      model: "llama3-8b-8192",
      temperature: 0.2,
      max_tokens: 400
    });

    const responseText = completion.choices[0]?.message?.content;
    if (!responseText) {
      throw new Error('No response from Groq');
    }

    // Clean and parse JSON response
    const cleanedResponse = responseText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    const riskAssessment = JSON.parse(cleanedResponse);

    logger.info('Groq risk assessment generated successfully');
    return riskAssessment;

  } catch (error) {
    logger.error('Error getting Groq risk assessment:', error);
    return null;
  }
}

// Helper function for simple rule-based risk assessment (fallback)
function simpleRiskAssessment(healthData) {
  const bmi = healthData.weight_pre_pregnancy ? 
    healthData.weight_pre_pregnancy / ((healthData.height / 100) ** 2) :
    healthData.bmi || 24;
    
  let riskLevel = 'Low Risk';
  const riskFactors = [];

  if (healthData.systolic_bp > 140 || healthData.diastolic_bp > 90) {
    riskLevel = 'Medium Risk';
    riskFactors.push('elevated blood pressure');
  }
  if (bmi > 30 || bmi < 18.5) {
    riskLevel = 'Medium Risk';
    riskFactors.push('BMI concerns');
  }
  if (healthData.gestational_age && healthData.gestational_age > 37) {
    riskLevel = 'Medium Risk';
    riskFactors.push('advanced gestational age');
  }
  if (healthData.age > 35) {
    riskLevel = 'Medium Risk';
    riskFactors.push('advanced maternal age');
  }
  if (healthData.blood_sugar > 125) {
    riskLevel = 'Medium Risk';
    riskFactors.push('elevated blood sugar');
  }

  if (riskFactors.length > 2) {
    riskLevel = 'High Risk';
  }

  return { riskLevel, riskFactors, bmi };
}

// Helper function to create string hash
function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash;
}

// Main health tips endpoint - Enhanced with Groq integration
router.get('/', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    const cacheKey = `health_tips_groq:${req.user.id}:${new Date().toISOString().split('T')[0]}`;

    // Check for force refresh parameter
    const forceRefresh = req.query.refresh === 'true';
    
    if (forceRefresh) {
      await deleteCached(cacheKey);
      logger.info(`Cache cleared for user ${req.user.id} due to force refresh`);
    }

    // Check in-memory cache first (unless force refresh)
    if (!forceRefresh) {
      const cachedTips = await getCached(cacheKey);
      if (cachedTips) {
        logger.info(`Returning cached health tips for user ${req.user.id}`);
        return res.json({
          ...cachedTips,
          fromCache: true,
          cacheTimestamp: cachedTips.timestamp
        });
      }
    }

    // Get user health data
    const healthData = await getUserHealthData(req.user.id, supabase);
    const maternalInput = prepareMaternalHealthInput(healthData);

    let aiRecommendations = null;
    let riskAssessment = null;
    let dataSource = 'rule-based';
    let apiErrors = [];

    // Try Groq AI APIs
    try {
      logger.info('Attempting Groq AI calls for health recommendations and risk assessment');
      
      // Call Groq for both recommendations and risk assessment
      const [recommendationsResult, riskResult] = await Promise.allSettled([
        getGroqHealthRecommendations(maternalInput),
        getGroqRiskAssessment(maternalInput)
      ]);

      // Process recommendations response
      if (recommendationsResult.status === 'fulfilled' && recommendationsResult.value) {
        aiRecommendations = recommendationsResult.value;
        logger.info('Groq health recommendations successful');
      } else {
        apiErrors.push(`Health recommendations: ${recommendationsResult.reason?.message || 'Failed'}`);
        logger.warn('Groq health recommendations failed:', recommendationsResult.reason);
      }

      // Process risk assessment response
      if (riskResult.status === 'fulfilled' && riskResult.value) {
        riskAssessment = riskResult.value;
        logger.info('Groq risk assessment successful');
      } else {
        apiErrors.push(`Risk assessment: ${riskResult.reason?.message || 'Failed'}`);
        logger.warn('Groq risk assessment failed:', riskResult.reason);
      }

      // If we got at least one successful response, mark as AI
      if (aiRecommendations || riskAssessment) {
        dataSource = 'groq-ai';
        logger.info(`Groq AI partially successful for user ${req.user.id}`, {
          has_recommendations: !!aiRecommendations,
          has_risk_assessment: !!riskAssessment
        });
      } else {
        dataSource = 'fallback-rules';
      }

    } catch (apiError) {
      logger.error('Groq AI error:', apiError.message);
      apiErrors.push(`Groq API error: ${apiError.message}`);
      dataSource = 'fallback-rules';
    }

    // Determine category for database tips lookup
    let category = 'general';
    if (aiRecommendations && aiRecommendations.category) {
      const categoryMap = {
        'Nutrition Focus': 'nutrition',
        'Exercise Focus': 'exercise',
        'Wellness Focus': 'mental_health',
        'General Focus': 'general'
      };
      category = categoryMap[aiRecommendations.category] || 'general';
    } else {
      // Enhanced fallback rule-based category determination
      if (maternalInput.blood_sugar > 125 || maternalInput.bmi > 30) {
        category = 'nutrition';
      } else if (maternalInput.bmi < 20 || Math.abs(maternalInput.weight_gain - 25) > 15) {
        category = 'exercise';
      } else if (maternalInput.heart_rate > 100 || 
                 (riskAssessment && riskAssessment.risk_level === 'High Risk') ||
                 maternalInput.systolic_bp > 140) {
        category = 'mental_health';
      }
    }

    // Fetch health tips from database with enhanced fallback
    let healthTips = [];
    
    if (DATABASE_FALLBACK_ENABLED) {
      healthTips = await fetchHealthTipsFromDatabase(supabase, category, healthData.gestationalWeek, req.user.id);
    }

    // If no tips from database, use default tips
    if (!healthTips || healthTips.length === 0) {
      logger.info(`No database tips found, using default tips for category: ${category}`);
      healthTips = createDefaultHealthTips(category, healthData.gestationalWeek);
    }

    // Generate fallback recommendations if Groq failed
    let fallbackRecommendations = null;
    if (!aiRecommendations) {
      const categoryTips = {
        nutrition: [
          'Focus on a balanced diet rich in fruits, vegetables, and whole grains',
          'Consider consulting a nutritionist for personalized meal planning',
          'Monitor your blood sugar levels regularly if you have diabetes concerns'
        ],
        exercise: [
          'Engage in moderate exercise as approved by your healthcare provider',
          'Consider prenatal yoga or swimming for low-impact fitness',
          'Listen to your body and rest when needed'
        ],
        mental_health: [
          'Practice stress management techniques like deep breathing or meditation',
          'Stay connected with your support network',
          'Don\'t hesitate to seek professional help if you feel overwhelmed'
        ],
        general: [
          'Maintain regular prenatal appointments with your healthcare provider',
          'Stay hydrated and get adequate rest',
          'Monitor your symptoms and report any concerns to your doctor'
        ]
      };

      fallbackRecommendations = {
        category: category,
        confidence: 0.75,
        tips: categoryTips[category] || categoryTips.general,
        source: 'rule-based-fallback'
      };
    }

    // Generate fallback risk assessment if needed
    let fallbackRiskAssessment = null;
    if (!riskAssessment) {
      // Simple rule-based risk assessment
      let riskLevel = 'Low Risk';
      let riskFactors = [];

      if (maternalInput.systolic_bp > 140 || maternalInput.diastolic_bp > 90) {
        riskLevel = 'Medium Risk';
        riskFactors.push('elevated blood pressure');
      }
      if (maternalInput.blood_sugar > 125) {
        riskLevel = 'Medium Risk';
        riskFactors.push('elevated blood sugar');
      }
      if (maternalInput.bmi > 35 || maternalInput.bmi < 18.5) {
        riskLevel = riskLevel === 'Low Risk' ? 'Medium Risk' : 'High Risk';
        riskFactors.push('BMI concerns');
      }
      if (maternalInput.heart_rate > 110) {
        riskLevel = 'Medium Risk';
        riskFactors.push('elevated heart rate');
      }

      if (riskFactors.length > 2) {
        riskLevel = 'High Risk';
      }

      fallbackRiskAssessment = {
        risk_level: riskLevel,
        confidence: 0.6,
        recommendation: riskFactors.length > 0 
          ? `Please discuss these factors with your healthcare provider: ${riskFactors.join(', ')}`
          : 'Continue with regular prenatal care and maintain healthy habits',
        risk_factors: riskFactors,
        source: 'rule-based-assessment'
      };
    }

    // Prepare comprehensive response
    const response = {
      currentWeek: Math.max(0, healthData.gestationalWeek),
      gestationalWeek: maternalInput.gestational_week,
      healthTips: healthTips || [],
      aiRecommendations: aiRecommendations || fallbackRecommendations,
      riskAssessment: riskAssessment || fallbackRiskAssessment,
      dataSource,
      apiStatus: {
        errors: apiErrors,
        healthTipsAPI: !!aiRecommendations ? 'success' : 'failed',
        riskAssessmentAPI: !!riskAssessment ? 'success' : 'failed',
        aiProvider: 'groq'
      },
      personalizedFor: {
        age: maternalInput.age,
        gestationalWeek: maternalInput.gestational_week,
        riskFactors: {
          hypertension: maternalInput.systolic_bp > 140 || maternalInput.diastolic_bp > 90,
          diabetes: maternalInput.blood_sugar > 125,
          weightConcerns: maternalInput.bmi < 18.5 || maternalInput.bmi > 30,
          heartRateElevated: maternalInput.heart_rate > 100
        }
      },
      metadata: {
        category,
        inputParameters: maternalInput,
        databaseTipsCount: (healthTips || []).length,
        useDefaultTips: healthTips === createDefaultHealthTips(category, healthData.gestationalWeek),
        forceRefresh
      },
      timestamp: new Date().toISOString(),
      fromCache: false
    };

    // Cache the response in memory (12 hours = 43200 seconds)
    await setCached(cacheKey, response, 12 * 60 * 60);
    logger.info(`Health tips cached for user ${req.user.id}, category: ${category}, tips: ${(healthTips || []).length}`);

    // Audit log with enhanced details
    auditLog('fetch_health_tips_groq', req.user.id, {
      week: healthData.gestationalWeek,
      source: dataSource,
      risk_level: (riskAssessment || fallbackRiskAssessment)?.risk_level,
      category: category,
      api_errors: apiErrors.length,
      tips_count: (healthTips || []).length,
      cached: false,
      force_refresh: forceRefresh
    });

    res.json(response);

  } catch (error) {
    logger.error('Get health tips error:', error);
    
    // Return a more informative error response
    const errorResponse = {
      error: 'Internal server error',
      message: 'Unable to fetch health tips at this time',
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || 'unknown'
    };

    // Don't expose internal error details in production
    if (process.env.NODE_ENV !== 'production') {
      errorResponse.details = error.message;
      errorResponse.stack = error.stack;
    }

    res.status(500).json(errorResponse);
  }
});

// Input validation middleware
const validateBasicHealthInput = (req, res, next) => {
  const requiredFields = ['age', 'gestational_age', 'weight_pre_pregnancy', 'height', 'systolic_bp', 'diastolic_bp'];
  const missingFields = requiredFields.filter(field => !req.body.hasOwnProperty(field) || req.body[field] == null);
  
  if (missingFields.length > 0) {
    return res.status(400).json({
      error: 'Invalid input',
      message: `Missing or invalid fields: ${missingFields.join(', ')}`,
      timestamp: new Date().toISOString()
    });
  }

  const numericFields = {
    age: { min: 15, max: 50 },
    gestational_age: { min: 0, max: 42 },
    weight_pre_pregnancy: { min: 30, max: 200 },
    height: { min: 100, max: 250 },
    systolic_bp: { min: 80, max: 200 },
    diastolic_bp: { min: 50, max: 120 }
  };

  for (const [field, { min, max }] of Object.entries(numericFields)) {
    const value = req.body[field];
    if (typeof value !== 'number' || value < min || value > max) {
      return res.status(400).json({
        error: 'Invalid input',
        message: `Field ${field} must be a number between ${min} and ${max}`,
        timestamp: new Date().toISOString()
      });
    }
  }

  next();
};

const validateChatInput = (req, res, next) => {
  const { message, user_id } = req.body;
  if (!message || !user_id) {
    return res.status(400).json({
      error: 'Invalid input',
      message: 'Both message and user_id are required',
      timestamp: new Date().toISOString()
    });
  }
  next();
};

const validateIntegratedConsultationInput = (req, res, next) => {
  const { message, user_id, health_data } = req.body;
  if (!message || !user_id || !health_data) {
    return res.status(400).json({
      error: 'Invalid input',
      message: 'message, user_id, and health_data are required',
      timestamp: new Date().toISOString()
    });
  }

  const requiredFields = ['age', 'gestational_age', 'weight_pre_pregnancy', 'height', 'systolic_bp', 'diastolic_bp'];
  const missingFields = requiredFields.filter(field => !health_data.hasOwnProperty(field) || health_data[field] == null);
  
  if (missingFields.length > 0) {
    return res.status(400).json({
      error: 'Invalid health data',
      message: `Missing or invalid fields: ${missingFields.join(', ')}`,
      timestamp: new Date().toISOString()
    });
  }

  next();
};

const validateComprehensiveHealthInput = (req, res, next) => {
  validateBasicHealthInput(req, res, next);
};


router.post('/risk-assessment', validateBasicHealthInput, async (req, res) => {
  try {
    const healthData = req.body;
    const cacheKey = `risk_assessment_groq:${hashCode(JSON.stringify(healthData))}`;
    
    const cachedResponse = await getCached(cacheKey);
    if (cachedResponse) {
      logger.info(`Returning cached risk assessment`);
      return res.json({ ...cachedResponse, fromCache: true });
    }

    // Prepare data for Groq
    const maternalInput = {
      age: healthData.age,
      gestational_week: healthData.gestational_age,
      systolic_bp: healthData.systolic_bp,
      diastolic_bp: healthData.diastolic_bp,
      bmi: healthData.weight_pre_pregnancy / ((healthData.height / 100) ** 2),
      heart_rate: healthData.heart_rate || 80,
      blood_sugar: healthData.blood_sugar || 95,
      body_temp: healthData.body_temp || 98.6,
      previous_pregnancies: healthData.previous_pregnancies || 0,
      weight_gain: healthData.weight_gain || 25
    };

    let groqAssessment = null;
    try {
      groqAssessment = await getGroqRiskAssessment(maternalInput);
    } catch (error) {
      logger.warn('Groq risk assessment failed, using fallback:', error);
    }

    // Fallback to simple assessment
    const { riskLevel, riskFactors, bmi } = simpleRiskAssessment(healthData);

    const response = {
      risk_assessment: groqAssessment || {
        risk_level: riskLevel,
        risk_factors: riskFactors,
        recommendation: riskFactors.length > 0 
          ? `Please discuss these factors with your healthcare provider: ${riskFactors.join(', ')}`
          : 'No significant risks detected. Continue regular monitoring.',
        confidence: 0.70,
        sources: ['rule_based_assessment'],
        health_metrics: {
          bmi: bmi.toFixed(1),
          blood_pressure_status: healthData.systolic_bp > 140 || healthData.diastolic_bp > 90 ? 'elevated' : 'normal',
          gestational_age: healthData.gestational_age
        }
      },
      dataSource: groqAssessment ? 'groq-ai' : 'rule-based',
      timestamp: new Date().toISOString(),
      fromCache: false
    };

    await setCached(cacheKey, response, CACHE_DURATION);
    
    auditLog('risk_assessment', null, {
      risk_level: response.risk_assessment.risk_level,
      risk_factors_count: (response.risk_assessment.risk_factors || []).length,
      data_source: response.dataSource,
      input_metrics: { age: healthData.age, gestational_age: healthData.gestational_age, bmi: bmi.toFixed(1) }
    });

    res.json(response);
  } catch (error) {
    logger.error('Risk assessment endpoint error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to process risk assessment request',
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || 'unknown'
    });
  }
});

// Enhanced Chat Endpoint with Groq
router.post("/chat", async (req, res) => {
  try {
    const { message, user_id } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Invalid input',
        message: 'Message is required',
        timestamp: new Date().toISOString()
      });
    }

    // Get user context if user_id is provided
    let userContext = '';
    if (user_id) {
      try {
        const supabase = getSupabaseClient();
        const healthData = await getUserHealthData(user_id, supabase);
        if (healthData && healthData.gestationalWeek) {
          userContext = `\n\nUser Context: Currently at ${healthData.gestationalWeek} weeks of pregnancy.`;
        }
      } catch (error) {
        logger.warn('Could not fetch user context for chat:', error);
      }
    }

    const chatCompletion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: `You are a maternal health assistant specializing in pregnancy care and support. 

Guidelines:
- Only discuss pregnancy, maternal care, childbirth, and related health topics
- Always include a disclaimer that this is not medical advice and users should consult healthcare providers
- Provide evidence-based, safe information
- Be empathetic and supportive while maintaining professional boundaries
- If asked about non-pregnancy topics, politely redirect to pregnancy-related matters
- Keep responses concise but informative (2-3 paragraphs max)
- Always encourage regular prenatal care

${userContext}`
        },
        { role: "user", content: message },
      ],
      model: "llama3-8b-8192",
      temperature: 0.7,
      max_tokens: 500
    });

    const reply = chatCompletion.choices[0]?.message?.content;

    if (!reply) {
      throw new Error('No response generated');
    }

    // Audit log
    if (user_id) {
      auditLog('chat_groq', user_id, {
        message_length: message.length,
        response_length: reply.length,
        has_user_context: !!userContext
      });
    }

    res.json({ 
      reply,
      timestamp: new Date().toISOString(),
      source: 'groq-ai'
    });

  } catch (err) {
    logger.error('Chat endpoint error:', err);
    res.status(500).json({ 
      error: 'Unable to process chat request',
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

router.post('/integrated-consultation', validateIntegratedConsultationInput, async (req, res) => {
  try {
    const { message, user_id, health_data } = req.body;
    const cacheKey = `integrated_consultation_groq:${user_id}:${hashCode(message)}:${hashCode(JSON.stringify(health_data))}`;
    
    const cachedResponse = await getCached(cacheKey);
    if (cachedResponse) {
      logger.info(`Returning cached integrated consultation for user ${user_id}`);
      return res.json({ ...cachedResponse, fromCache: true });
    }

    const supabase = getSupabaseClient();
    const pregnancyData = await getUserHealthData(user_id, supabase);
    const { riskLevel, riskFactors, bmi } = simpleRiskAssessment(health_data);

    // Prepare detailed health context for Groq
    const healthContext = `
Patient Health Data:
- Age: ${health_data.age} years
- Gestational Age: ${health_data.gestational_age} weeks
- Blood Pressure: ${health_data.systolic_bp}/${health_data.diastolic_bp} mmHg
- BMI: ${bmi.toFixed(1)}
- Risk Level: ${riskLevel}
- Risk Factors: ${riskFactors.join(', ') || 'None identified'}

Patient Question: ${message}
    `;

    let groqResponse = null;
    try {
      const consultation = await groq.chat.completions.create({
        messages: [
          {
            role: "system",
            content: `You are a maternal health AI assistant providing consultation based on health data and patient questions.

Guidelines:
- Analyze the provided health data in context of the patient's question
- Provide personalized, evidence-based guidance
- Always emphasize consulting healthcare providers for concerning symptoms
- Be empathetic and supportive
- Keep responses focused and actionable (2-3 paragraphs)
- Include specific recommendations based on risk factors if any
- Always include medical disclaimer`
          },
          { role: "user", content: healthContext }
        ],
        model: "llama3-8b-8192",
        temperature: 0.6,
        max_tokens: 600
      });

      groqResponse = consultation.choices[0]?.message?.content;
    } catch (error) {
      logger.warn('Groq consultation failed:', error);
    }

    let responseContent;
    if (groqResponse) {
      responseContent = {
        message: groqResponse,
        confidence: 0.8,
        sources: ['groq-ai', 'provided_health_data'],
        health_metrics: {
          bmi: bmi.toFixed(1),
          blood_pressure_status: health_data.systolic_bp > 140 || health_data.diastolic_bp > 90 ? 'elevated' : 'normal',
          gestational_age: health_data.gestational_age
        },
        timestamp: new Date().toISOString()
      };
    } else {
      // Fallback response
      responseContent = {
        message: `Based on your health data (BP: ${health_data.systolic_bp}/${health_data.diastolic_bp}, BMI: ${bmi.toFixed(1)}), your risk level is ${riskLevel}. ${riskFactors.length > 0 ? 'Areas of concern: ' + riskFactors.join(', ') + '. Please discuss these with your healthcare provider.' : 'No immediate concerns detected, but regular checkups are recommended.'} 

Please consult your healthcare provider for personalized medical advice regarding your specific question.`,
        confidence: 0.7,
        sources: ['rule_based_assessment', 'provided_health_data'],
        health_metrics: {
          bmi: bmi.toFixed(1),
          blood_pressure_status: health_data.systolic_bp > 140 || health_data.diastolic_bp > 90 ? 'elevated' : 'normal',
          gestational_age: health_data.gestational_age
        },
        timestamp: new Date().toISOString()
      };
    }

    const response = {
      response: responseContent,
      user_id,
      risk_level: riskLevel,
      risk_factors: riskFactors,
      pregnancy_status: pregnancyData ? 'active' : 'no_active_pregnancy',
      dataSource: groqResponse ? 'groq-ai' : 'rule-based',
      fromCache: false
    };

    await setCached(cacheKey, response, CACHE_DURATION);
    
    auditLog('integrated_consultation', user_id, {
      message,
      risk_level: riskLevel,
      risk_factors_count: riskFactors.length,
      has_pregnancy: !!pregnancyData,
      data_source: response.dataSource
    });

    res.json(response);
  } catch (error) {
    logger.error('Integrated consultation endpoint error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to process consultation request',
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || 'unknown'
    });
  }
});

// Report Endpoints - Updated with Groq
router.post('/health-report', validateComprehensiveHealthInput, async (req, res) => {
  try {
    const healthData = req.body;
    const cacheKey = `health_report_groq:${hashCode(JSON.stringify(healthData))}`;
    
    const cachedResponse = await getCached(cacheKey);
    if (cachedResponse) {
      logger.info(`Returning cached health report`);
      return res.json({ ...cachedResponse, fromCache: true });
    }

    const { riskLevel, riskFactors, bmi } = simpleRiskAssessment(healthData);

    // Try to get Groq-generated health report
    let groqReport = null;
    try {
      const reportPrompt = `Generate a comprehensive health report for a pregnant patient with the following data:

Age: ${healthData.age} years
Gestational Age: ${healthData.gestational_age} weeks  
Blood Pressure: ${healthData.systolic_bp}/${healthData.diastolic_bp} mmHg
BMI: ${bmi.toFixed(1)}
Risk Factors: ${riskFactors.join(', ') || 'None identified'}

Provide a JSON response with:
{
  "risk_level": "${riskLevel}",
  "recommendations": ["rec1", "rec2", "rec3"],
  "health_summary": "brief summary of overall health status",
  "next_steps": ["step1", "step2"],
  "source": "groq-ai"
}`;

      const completion = await groq.chat.completions.create({
        messages: [
          {
            role: "system", 
            content: "You are a maternal health AI generating comprehensive health reports. Respond only in valid JSON format."
          },
          { role: "user", content: reportPrompt }
        ],
        model: "llama3-8b-8192",
        temperature: 0.3,
        max_tokens: 500
      });

      const responseText = completion.choices[0]?.message?.content;
      if (responseText) {
        const cleanedResponse = responseText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        groqReport = JSON.parse(cleanedResponse);
      }
    } catch (error) {
      logger.warn('Groq health report failed:', error);
    }

    const response = {
      health_report: groqReport || {
        risk_level: riskLevel,
        risk_factors: riskFactors,
        recommendations: [
          'Maintain regular prenatal checkups',
          ...(riskFactors.length > 0 ? [`Address concerns: ${riskFactors.join(', ')} with your healthcare provider`] : []),
          'Follow a balanced diet and stay hydrated',
          'Engage in approved physical activity'
        ],
        health_metrics: {
          bmi: bmi.toFixed(1),
          blood_pressure_status: healthData.systolic_bp > 140 || healthData.diastolic_bp > 90 ? 'elevated' : 'normal',
          gestational_age: healthData.gestational_age,
          age: healthData.age
        },
        confidence: 0.75,
        sources: ['rule_based_report', 'health_data'],
        timestamp: new Date().toISOString()
      },
      dataSource: groqReport ? 'groq-ai' : 'rule-based',
      fromCache: false
    };

    await setCached(cacheKey, response, CACHE_DURATION);
    
    auditLog('health_report', null, {
      risk_level: riskLevel,
      risk_factors_count: riskFactors.length,
      data_source: response.dataSource,
      input_metrics: { age: healthData.age, gestational_age: healthData.gestational_age, bmi: bmi.toFixed(1) }
    });

    res.json(response);
  } catch (error) {
    logger.error('Health report endpoint error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to generate health report',
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || 'unknown'
    });
  }
});

// Health Assessment endpoint - Updated with Groq
router.get('/health-assessment', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    const cacheKey = `health_assessment_groq:${req.user.id}:${new Date().toISOString().split('T')[0]}`;

    // Check cache first
    const cachedAssessment = await getCached(cacheKey);
    if (cachedAssessment) {
      logger.info(`Returning cached health assessment for user ${req.user.id}`);
      return res.json({
        ...cachedAssessment,
        fromCache: true
      });
    }

    // Get user health data
    const healthData = await getUserHealthData(req.user.id, supabase);
    const maternalInput = prepareMaternalHealthInput(healthData);

    let aiRecommendations = null;
    let riskAssessment = null;
    let dataSource = 'rule-based';

    // Try Groq APIs
    try {
      const [tipsResult, riskResult] = await Promise.allSettled([
        getGroqHealthRecommendations(maternalInput),
        getGroqRiskAssessment(maternalInput)
      ]);

      if (tipsResult.status === 'fulfilled' && tipsResult.value) {
        aiRecommendations = tipsResult.value;
      }

      if (riskResult.status === 'fulfilled' && riskResult.value) {
        riskAssessment = riskResult.value;
      }

      if (aiRecommendations || riskAssessment) {
        dataSource = 'groq-ai';
      }
    } catch (error) {
      logger.error('Groq API error in health assessment:', error);
    }

    // Generate fallback risk assessment if needed
    if (!riskAssessment) {
      const { riskLevel, riskFactors } = simpleRiskAssessment({
        age: maternalInput.age,
        gestational_age: maternalInput.gestational_week - 12,
        weight_pre_pregnancy: 65,
        height: 165,
        systolic_bp: maternalInput.systolic_bp,
        diastolic_bp: maternalInput.diastolic_bp
      });

      riskAssessment = {
        risk_level: riskLevel,
        confidence: 0.65,
        recommendation: riskFactors.length > 0 
          ? `Please discuss these factors with your healthcare provider: ${riskFactors.join(', ')}`
          : 'Continue with regular prenatal care and maintain healthy habits'
      };
    }

    // Generate fallback recommendations if needed
    if (!aiRecommendations) {
      let category = 'general';
      const tips = ['Maintain regular prenatal checkups', 'Stay hydrated', 'Take prenatal vitamins'];
      
      if (maternalInput.systolic_bp > 140) {
        category = 'mental_health';
        tips.push('Practice stress management techniques', 'Monitor blood pressure regularly');
      } else if (maternalInput.bmi > 30) {
        category = 'nutrition';
        tips.push('Focus on balanced nutrition', 'Consult with a nutritionist');
      }

      aiRecommendations = {
        category: category,
        confidence: 0.6,
        tips: tips
      };
    }

    // Mock risk factors for detailed analysis
    const riskFactors = [
      {
        factor: 'Age',
        level: maternalInput.age > 35 ? 'Medium' : 'Low',
        description: `Age ${maternalInput.age} years`,
        impact: maternalInput.age > 35 ? 'Advanced maternal age may increase certain risks' : 'Age within normal range'
      },
      {
        factor: 'Blood Pressure',
        level: maternalInput.systolic_bp > 140 ? 'High' : maternalInput.systolic_bp > 120 ? 'Medium' : 'Low',
        description: `BP ${maternalInput.systolic_bp}/${maternalInput.diastolic_bp} mmHg`,
        impact: maternalInput.systolic_bp > 140 ? 'Elevated blood pressure requires monitoring' : 'Blood pressure within normal range'
      },
      {
        factor: 'BMI',
        level: maternalInput.bmi > 30 ? 'High' : maternalInput.bmi < 18.5 ? 'Medium' : 'Low',
        description: `BMI ${maternalInput.bmi.toFixed(1)}`,
        impact: maternalInput.bmi > 30 ? 'High BMI may increase pregnancy complications' : 'BMI within acceptable range'
      }
    ];

    const response = {
      currentWeek: healthData.gestationalWeek,
      riskAssessment,
      aiRecommendations,
      riskFactors,
      dataSource,
      timestamp: new Date().toISOString()
    };

    // Cache for 6 hours
    await setCached(cacheKey, response, 6 * 60 * 60);

    auditLog('health_assessment', req.user.id, {
      risk_level: riskAssessment.risk_level,
      data_source: dataSource,
      week: healthData.gestationalWeek
    });

    res.json(response);

  } catch (error) {
    logger.error('Health assessment error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to fetch health assessment',
      timestamp: new Date().toISOString()
    });
  }
});

// Detailed Report endpoint - Updated with Groq
router.get('/detailed-report', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    const healthData = await getUserHealthData(req.user.id, supabase);
    const maternalInput = prepareMaternalHealthInput(healthData);

    // Generate comprehensive report data
    const { riskLevel, riskFactors } = simpleRiskAssessment({
      age: maternalInput.age,
      gestational_age: maternalInput.gestational_week - 12,
      weight_pre_pregnancy: 65,
      height: 165,
      systolic_bp: maternalInput.systolic_bp,
      diastolic_bp: maternalInput.diastolic_bp
    });

    // Try to get Groq-enhanced detailed report
    let groqAssessment = null;
    let groqRecommendations = null;
    let dataSource = 'rule-based';

    try {
      const [assessmentResult, recommendationsResult] = await Promise.allSettled([
        getGroqRiskAssessment(maternalInput),
        getGroqHealthRecommendations(maternalInput)
      ]);

      if (assessmentResult.status === 'fulfilled' && assessmentResult.value) {
        groqAssessment = assessmentResult.value;
        dataSource = 'groq-ai';
      }

      if (recommendationsResult.status === 'fulfilled' && recommendationsResult.value) {
        groqRecommendations = recommendationsResult.value;
        dataSource = 'groq-ai';
      }
    } catch (error) {
      logger.warn('Groq detailed report failed:', error);
    }

    const response = {
      assessmentData: {
        riskAssessment: groqAssessment || {
          risk_level: riskLevel,
          confidence: 0.75,
          recommendation: riskFactors.length > 0 
            ? `Key areas to discuss with your healthcare provider: ${riskFactors.join(', ')}`
            : 'Your current health metrics show no immediate concerns. Continue with regular prenatal care.'
        },
        aiRecommendations: groqRecommendations || {
          category: 'General Focus',
          confidence: 0.7,
          tips: [
            'Maintain regular prenatal appointments',
            'Follow a balanced diet rich in nutrients',
            'Stay physically active as approved by your doctor',
            'Monitor your symptoms and report any concerns'
          ]
        },
        currentWeek: healthData.gestationalWeek
      },
      riskFactors: [
        {
          factor: 'Maternal Age',
          level: maternalInput.age > 35 ? 'Medium' : 'Low',
          value: `${maternalInput.age} years`,
          description: maternalInput.age > 35 ? 'Advanced maternal age' : 'Age within optimal range',
          impact: maternalInput.age > 35 ? 'May require additional monitoring' : 'No additional concerns',
          recommendation: maternalInput.age > 35 ? 'Discuss genetic screening options with your provider' : 'Continue standard care'
        },
        {
          factor: 'Blood Pressure',
          level: maternalInput.systolic_bp > 140 ? 'High' : 'Low',
          value: `${maternalInput.systolic_bp}/${maternalInput.diastolic_bp} mmHg`,
          description: maternalInput.systolic_bp > 140 ? 'Elevated blood pressure' : 'Normal blood pressure',
          impact: maternalInput.systolic_bp > 140 ? 'Increased risk of preeclampsia' : 'Healthy cardiovascular status',
          recommendation: maternalInput.systolic_bp > 140 ? 'Regular BP monitoring and lifestyle modifications' : 'Maintain current healthy habits'
        }
      ],
      dataSource
    };

    auditLog('detailed_report', req.user.id, {
      risk_level: riskLevel,
      data_source: dataSource,
      week: healthData.gestationalWeek
    });

    res.json(response);

  } catch (error) {
    logger.error('Detailed report error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to generate detailed report',
      timestamp: new Date().toISOString()
    });
  }
});

// Doctors endpoint (called by ConsultationScreen)
router.get('/doctors', async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    // Try to fetch from database first
    const { data: doctors, error } = await supabase
      .from('users')
      .select('*')
      .eq('status', 'doctor')
      .order('rating', { ascending: false });

    if (error) {
      logger.warn('Database doctors query error:', error);
    }

    // If no doctors in database, return mock data
    const mockDoctors = [
      {
        id: 1,
        name: 'Dr. Sarah Johnson',
        specialty: 'Obstetrician & Gynecologist',
        experience: '12 years',
        rating: 4.8,
        image: 'https://images.unsplash.com/photo-1559839734-2b71ea197ec2?w=400&h=400&fit=crop&crop=face',
        nextAvailable: 'Today, 2:00 PM',
        consultationFee: '$75',
        languages: ['English', 'Spanish']
      },
      {
        id: 2,
        name: 'Dr. Michael Chen',
        specialty: 'Maternal-Fetal Medicine',
        experience: '15 years',
        rating: 4.9,
        image: 'https://images.unsplash.com/photo-1612349317150-e413f6a5b16d?w=400&h=400&fit=crop&crop=face',
        nextAvailable: 'Tomorrow, 10:00 AM',
        consultationFee: '$85',
        languages: ['English', 'Mandarin']
      },
      {
        id: 3,
        name: 'Dr. Emily Rodriguez',
        specialty: 'High-Risk Pregnancy Specialist',
        experience: '10 years',
        rating: 4.7,
        image: 'https://images.unsplash.com/photo-1594824949417-772a4935c7ad?w=400&h=400&fit=crop&crop=face',
        nextAvailable: 'Today, 4:30 PM',
        consultationFee: '$90',
        languages: ['English', 'Spanish', 'French']
      }
    ];

    auditLog('fetch_doctors', req.user.id, {
      doctors_count: doctors?.length || mockDoctors.length,
      source: doctors?.length ? 'database' : 'mock'
    });

    res.json({
      doctors: doctors?.length ? doctors : mockDoctors,
      source: doctors?.length ? 'database' : 'mock',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Doctors endpoint error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to fetch doctors',
      timestamp: new Date().toISOString()
    });
  }
});

// Health tips by category endpoint (called by HealthTipsScreen)
router.get('/category/:category', async (req, res) => {
  try {
    const { category } = req.params;
    const supabase = getSupabaseClient();
    const healthData = await getUserHealthData(req.user.id, supabase);

    // Fetch tips for specific category
    const healthTips = await fetchHealthTipsFromDatabase(
      supabase, 
      category, 
      healthData?.gestationalWeek || 0, 
      req.user.id
    );

    // If no tips found, use default tips for category
    const finalTips = healthTips.length > 0 
      ? healthTips 
      : createDefaultHealthTips(category, healthData?.gestationalWeek || 0);

    auditLog('fetch_category_tips', req.user.id, {
      category,
      tips_count: finalTips.length,
      week: healthData?.gestationalWeek || 0
    });

    res.json({
      healthTips: finalTips,
      category,
      gestationalWeek: healthData?.gestationalWeek || 0,
      source: healthTips.length > 0 ? 'database' : 'default',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Category tips endpoint error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: 'Unable to fetch category tips',
      timestamp: new Date().toISOString()
    });
  }
});

// Add a debug endpoint to check database health tips
router.get('/debug/database-tips', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    
    // Get count of tips by category
    const { data: tipCounts, error } = await supabase
      .from('health_tips')
      .select('category, id')
      .order('category');

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    const categoryCounts = {};
    (tipCounts || []).forEach(tip => {
      categoryCounts[tip.category] = (categoryCounts[tip.category] || 0) + 1;
    });

    // Get sample tips from each category
    const sampleTips = {};
    for (const category of ['general', 'nutrition', 'exercise', 'mental_health']) {
      const { data: samples } = await supabase
        .from('health_tips')
        .select('id, title, content, week_start, week_end')
        .eq('category', category)
        .limit(2);
      
      sampleTips[category] = samples || [];
    }

    res.json({
      totalTips: (tipCounts || []).length,
      categoryCounts,
      sampleTips,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Debug database tips error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add endpoint to clear cache for specific user
router.delete('/cache/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const today = new Date().toISOString().split('T')[0];
    
    const cacheKeys = [
      `health_tips_groq:${userId}:${today}`,
      `health_assessment_groq:${userId}:${today}`,
      `health_tips_v3:${userId}:${today}`, // Legacy key
      `health_tips_v2:${userId}:${today}`, // Legacy key
      `assessment:${userId}:${today}` // Legacy key
    ];

    for (const key of cacheKeys) {
      await deleteCached(key);
    }

    logger.info(`Cache cleared for user ${userId}`);
    res.json({ 
      message: `Cache cleared for user ${userId}`,
      keysCleared: cacheKeys,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Clear user cache error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add endpoint to test Groq connection
router.get('/debug/groq-test', async (req, res) => {
  try {
    if (!process.env.GROQ_API_KEY) {
      return res.status(500).json({
        error: 'GROQ_API_KEY not configured',
        timestamp: new Date().toISOString()
      });
    }

    const testCompletion = await groq.chat.completions.create({
      messages: [
        {
          role: "system",
          content: "You are a test assistant. Respond with 'Groq connection successful' if you receive this message."
        },
        {
          role: "user", 
          content: "Test connection"
        }
      ],
      model: "llama3-8b-8192",
      max_tokens: 50
    });

    const response = testCompletion.choices[0]?.message?.content;

    res.json({
      status: 'success',
      response,
      model: 'llama3-8b-8192',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Groq test error:', error);
    res.status(500).json({
      error: 'Groq connection failed',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router;