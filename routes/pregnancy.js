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

    // Validate dates
    if (!start_date || !due_date) {
      return res.status(400).json({ error: 'Start date and due date are required' });
    }

    const startDateObj = new Date(start_date);
    const dueDateObj = new Date(due_date);
    const today = new Date();

    if (startDateObj > today) {
      return res.status(400).json({ error: 'Start date cannot be in the future' });
    }

    if (dueDateObj <= startDateObj) {
      return res.status(400).json({ error: 'Due date must be after start date' });
    }

    // Check if user already has an active pregnancy
    const { data: existingPregnancy, error: checkError } = await supabase
      .from('pregnancies')
      .select('id')
      .eq('user_id', req.user.userId) // Fixed: use userId from JWT payload
      .eq('status', 'active')
      .maybeSingle();

    if (checkError) {
      logger.error('Check existing pregnancy error:', checkError);
      return res.status(500).json({ error: 'Database error' });
    }

    if (existingPregnancy) {
      return res.status(409).json({ error: 'User already has an active pregnancy' });
    }

    // Create pregnancy record
    const { data: pregnancy, error } = await supabase
      .from('pregnancies')
      .insert([{
        user_id: req.user.userId, // Fixed: use userId from JWT payload
        start_date,
        due_date,
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) {
      logger.error('Pregnancy creation error:', error);
      return res.status(500).json({ error: 'Failed to create pregnancy record' });
    }

    logger.info(`Pregnancy record created for user ${req.user.userId}`);

    res.status(201).json({
      message: 'Pregnancy record created successfully',
      pregnancy
    });

  } catch (error) {
    logger.error('Create pregnancy error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's pregnancies
router.get('/', authenticateToken, async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancies, error } = await supabase
      .from('pregnancies')
      .select('*')
      .eq('user_id', req.user.userId) // Fixed: use userId from JWT payload
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
      .eq('user_id', req.user.userId) // Fixed: use userId from JWT payload
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
      .eq('user_id', req.user.userId) // Fixed: use userId from JWT payload
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
      .eq('user_id', req.user.userId);

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