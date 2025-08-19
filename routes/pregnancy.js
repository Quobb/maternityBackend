const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { validatePregnancy } = require('../middleware/validation');
const { authenticateToken } = require('../middleware/auth'); // Fixed import
const logger = require('../utils/logger');

const router = express.Router();

// Create pregnancy record
router.post('/', authenticateToken, validatePregnancy, async (req, res) => {
  try {
    const { start_date, due_date } = req.body;
    const supabase = getSupabaseClient();

    // Enhanced logging for debugging
    console.log('=== PREGNANCY CREATION DEBUG ===');
    console.log('User from token:', req.user);
    console.log('Request body:', req.body);
    console.log('User ID:', req.user?.id || req.user?.userId || req.user?.user_id);

    // Validate dates
    if (!start_date || !due_date) {
      logger.warn('Missing required dates:', { start_date, due_date });
      return res.status(400).json({ error: 'Start date and due date are required' });
    }

    // Enhanced date validation
    let startDateObj, dueDateObj;
    try {
      startDateObj = new Date(start_date);
      dueDateObj = new Date(due_date);
      
      // Check if dates are valid
      if (isNaN(startDateObj.getTime()) || isNaN(dueDateObj.getTime())) {
        return res.status(400).json({ error: 'Invalid date format' });
      }
    } catch (dateError) {
      logger.error('Date parsing error:', dateError);
      return res.status(400).json({ error: 'Invalid date format' });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0); // Reset time for fair comparison

    if (startDateObj > today) {
      return res.status(400).json({ error: 'Start date cannot be in the future' });
    }

    if (dueDateObj <= startDateObj) {
      return res.status(400).json({ error: 'Due date must be after start date' });
    }

    // Get user ID with fallback options
    const userId = req.user?.id || req.user?.userId || req.user?.user_id;
    if (!userId) {
      logger.error('No user ID found in token:', req.user);
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    console.log('Using user ID:', userId);

    // Test database connection first
    try {
      const { data: testQuery, error: testError } = await supabase
        .from('pregnancies')
        .select('id')
        .limit(1);
      
      if (testError) {
        logger.error('Database connection test failed:', testError);
        return res.status(500).json({ error: 'Database connection failed', details: testError.message });
      }
      console.log('Database connection successful');
    } catch (connectionError) {
      logger.error('Database connection error:', connectionError);
      return res.status(500).json({ error: 'Database connection failed' });
    }

    // Check if user already has an active pregnancy
    console.log('Checking for existing pregnancy...');
    const { data: existingPregnancy, error: checkError } = await supabase
      .from('pregnancies')
      .select('id, status, start_date, due_date')
      .eq('user_id', userId)
      .eq('status', 'active');

    if (checkError) {
      logger.error('Check existing pregnancy error:', checkError);
      console.log('Check error details:', {
        message: checkError.message,
        details: checkError.details,
        hint: checkError.hint,
        code: checkError.code
      });
      return res.status(500).json({ 
        error: 'Database error during pregnancy check', 
        details: checkError.message 
      });
    }

    console.log('Existing pregnancy check result:', existingPregnancy);

    if (existingPregnancy && existingPregnancy.length > 0) {
      logger.info(`User ${userId} already has active pregnancy:`, existingPregnancy[0]);
      return res.status(409).json({ 
        error: 'User already has an active pregnancy',
        existing_pregnancy: existingPregnancy[0]
      });
    }

    // Prepare pregnancy data
    const pregnancyData = {
      user_id: userId,
      start_date: start_date,
      due_date: due_date,
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    console.log('Creating pregnancy with data:', pregnancyData);

    // Create pregnancy record with detailed error handling
    const { data: pregnancy, error } = await supabase
      .from('pregnancies')
      .insert([pregnancyData])
      .select()
      .single();

    if (error) {
      logger.error('Pregnancy creation error:', error);
      console.log('Creation error details:', {
        message: error.message,
        details: error.details,
        hint: error.hint,
        code: error.code
      });

      // Handle specific Supabase errors
      if (error.code === '23505') { // Unique constraint violation
        return res.status(409).json({ error: 'Pregnancy record already exists' });
      } else if (error.code === '23503') { // Foreign key constraint violation
        return res.status(400).json({ error: 'Invalid user reference' });
      } else if (error.code === '42703') { // Undefined column
        return res.status(500).json({ error: 'Database schema error', details: error.message });
      } else if (error.code === '42P01') { // Undefined table
        return res.status(500).json({ error: 'Database table not found', details: error.message });
      }

      return res.status(500).json({ 
        error: 'Failed to create pregnancy record', 
        details: error.message,
        code: error.code 
      });
    }

    if (!pregnancy) {
      logger.error('Pregnancy creation returned no data');
      return res.status(500).json({ error: 'Pregnancy creation failed - no data returned' });
    }

    logger.info(`Pregnancy record created successfully for user ${userId}:`, pregnancy);
    console.log('=== PREGNANCY CREATION SUCCESS ===');

    res.status(201).json({
      message: 'Pregnancy record created successfully',
      pregnancy: {
        id: pregnancy.id,
        user_id: pregnancy.user_id,
        start_date: pregnancy.start_date,
        due_date: pregnancy.due_date,
        status: pregnancy.status,
        created_at: pregnancy.created_at
      }
    });

  } catch (error) {
    logger.error('Create pregnancy unexpected error:', error);
    console.log('Unexpected error details:', {
      name: error.name,
      message: error.message,
      stack: error.stack
    });
    
    res.status(500).json({ 
      error: 'Internal server error', 
      details: process.env.NODE_ENV === 'development' ? error.message : 'Contact support'
    });
  }
});

// Get user's pregnancies
router.get('/', authenticateToken, async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancies, error } = await supabase
      .from('pregnancies')
      .select('*')
      .eq('user_id', req.user.id) // Fixed: use userId from JWT payload
      .order('created_at', { ascending: false });

    if (error) {
      logger.error('Get pregnancies error:', error);
      return res.status(500).json({ error: 'Failed to fetch pregnancies' });
    }

    res.json({ pregnancies });

  } catch (error) {
    logger.error('Get pregnancies error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current pregnancy
router.get('/current', authenticateToken, async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancy, error } = await supabase
      .from('pregnancies')
      .select('*')
      .eq('user_id', req.user.id) // Fixed: use userId from JWT payload
      .eq('status', 'active')
      .maybeSingle();

    if (error) {
      logger.error('Get current pregnancy error:', error);
      return res.status(500).json({ error: 'Failed to fetch current pregnancy' });
    }

    if (!pregnancy) {
      return res.status(404).json({ error: 'No active pregnancy found' });
    }

    // Calculate pregnancy week
    const startDate = new Date(pregnancy.start_date);
    const currentDate = new Date();
    const weeksDiff = Math.floor((currentDate - startDate) / (7 * 24 * 60 * 60 * 1000));

    res.json({
      pregnancy: {
        ...pregnancy,
        current_week: Math.max(0, weeksDiff)
      }
    });

  } catch (error) {
    logger.error('Get current pregnancy error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update pregnancy status
router.patch('/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const supabase = getSupabaseClient();

    if (!['active', 'completed', 'terminated'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const { data: pregnancy, error } = await supabase
      .from('pregnancies')
      .update({
        status,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .eq('user_id', req.user.id) // Fixed: use userId from JWT payload
      .select()
      .single();

    if (error) {
      logger.error('Update pregnancy error:', error);
      return res.status(500).json({ error: 'Failed to update pregnancy' });
    }

    if (!pregnancy) {
      return res.status(404).json({ error: 'Pregnancy not found or unauthorized' });
    }

    res.json({
      message: 'Pregnancy status updated successfully',
      pregnancy
    });

  } catch (error) {
    logger.error('Update pregnancy status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Calculate due date endpoint
router.post('/calculate-due-date', authenticateToken, async (req, res) => {
  try {
    const { lmp_date } = req.body; // Last Menstrual Period date
    
    if (!lmp_date) {
      return res.status(400).json({ error: 'LMP date is required' });
    }

    const lmpDateObj = new Date(lmp_date);
    
    // Validate LMP date
    if (!lmpDateObj.getTime()) {
      return res.status(400).json({ error: 'Invalid LMP date format' });
    }

    const today = new Date();
    if (lmpDateObj > today) {
      return res.status(400).json({ error: 'LMP date cannot be in the future' });
    }

    // Check if LMP is too far in the past (more than 10 months)
    const tenMonthsAgo = new Date();
    tenMonthsAgo.setMonth(today.getMonth() - 10);
    if (lmpDateObj < tenMonthsAgo) {
      return res.status(400).json({ error: 'LMP date seems too far in the past' });
    }

    // Naegele's Rule: LMP + 280 days (40 weeks)
    const dueDate = new Date(lmpDateObj);
    dueDate.setDate(lmpDateObj.getDate() + 280);

    // Calculate current week
    const weeksDiff = Math.floor((today - lmpDateObj) / (7 * 24 * 60 * 60 * 1000));
    const currentWeek = Math.max(0, weeksDiff);

    res.json({ 
      due_date: dueDate.toISOString().split('T')[0],
      current_week: currentWeek,
      gestational_age: `${Math.floor(currentWeek)} weeks ${(currentWeek % 1) * 7} days`
    });

  } catch (error) {
    logger.error('Calculate due date error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get pregnancy statistics
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancies, error } = await supabase
      .from('pregnancies')
      .select('status')
      .eq('user_id', req.user.id);

    if (error) {
      logger.error('Get pregnancy stats error:', error);
      return res.status(500).json({ error: 'Failed to fetch pregnancy statistics' });
    }

    const stats = {
      total: pregnancies.length,
      active: pregnancies.filter(p => p.status === 'active').length,
      completed: pregnancies.filter(p => p.status === 'completed').length,
      terminated: pregnancies.filter(p => p.status === 'terminated').length
    };

    res.json({ stats });

  } catch (error) {
    logger.error('Get pregnancy stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;