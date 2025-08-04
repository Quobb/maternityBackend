const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { validatePregnancy } = require('../middleware/validation');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Create pregnancy record
router.post('/', requireRole(['mother']), validatePregnancy, async (req, res) => {
  try {
    const { start_date, due_date } = req.body;
    const supabase = getSupabaseClient();

    // Check if user already has an active pregnancy
    const { data: existingPregnancy } = await supabase
      .from('pregnancies')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .single();

    if (existingPregnancy) {
      return res.status(409).json({ error: 'User already has an active pregnancy' });
    }

    const pregnancyId = uuidv4();
    const { data: pregnancy, error } = await supabase
      .from('pregnancies')
      .insert([{
        id: pregnancyId,
        user_id: req.user.id,
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

    res.status(201).json({
      message: 'Pregnancy record created successfully',
      pregnancy
    });
    // Inside POST / route, after successful insert
    auditLog('create_pregnancy', req.user.id, { pregnancyId });

  } catch (error) {
    logger.error('Create pregnancy error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's pregnancies
router.get('/', async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancies, error } = await supabase
      .from('pregnancies')
      .select('*')
      .eq('user_id', req.user.id)
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
router.get('/current', async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: pregnancy, error } = await supabase
      .from('pregnancies')
      .select('*')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .single();

    if (error && error.code !== 'PGRST116') { // PGRST116 is "not found"
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
router.patch('/:id/status', async (req, res) => {
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
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      logger.error('Update pregnancy error:', error);
      return res.status(500).json({ error: 'Failed to update pregnancy' });
    }

    if (!pregnancy) {
      return res.status(404).json({ error: 'Pregnancy not found' });
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


// routes/pregnancy.js (Add to existing file)
router.post('/calculate-due-date', requireRole(['mother']), async (req, res) => {
  try {
    const { lmp_date } = req.body; // Last Menstrual Period date
    if (!lmp_date || !new Date(lmp_date).getTime()) {
      return res.status(400).json({ error: 'Valid LMP date required' });
    }

    // Naegele’s Rule: LMP + 1 year - 3 months + 7 days
    const lmp = new Date(lmp_date);
    const dueDate = new Date(lmp);
    dueDate.setFullYear(lmp.getFullYear() + 1);
    dueDate.setMonth(lmp.getMonth() - 3);
    dueDate.setDate(lmp.getDate() + 7);

    res.json({ due_date: dueDate.toISOString().split('T')[0] });
  } catch (error) {
    logger.error('Calculate due date error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
