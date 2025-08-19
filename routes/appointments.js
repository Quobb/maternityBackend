const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { validateAppointment } = require('../middleware/validation');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Create appointment
router.post('/', requireRole(['mother']), validateAppointment, async (req, res) => {
  try {
    const { doctor_id, scheduled_at, notes,type } = req.body;
    const supabase = getSupabaseClient();

    // Verify doctor exists and has correct role
    const { data: doctor } = await supabase
      .from('users')
      .select('id, role')
      .eq('id', doctor_id)
      .eq('role', 'doctor')
      .single();

    if (!doctor) {
      return res.status(404).json({ error: 'Doctor not found' });
    }

    const appointmentId = uuidv4();
    const { data: appointment, error } = await supabase
      .from('appointments')
      .insert([{
        id: appointmentId,
        user_id: req.user.id,
        type,
        doctor_id,
        scheduled_at,
        status: 'scheduled',
        notes
      }])
      .select(`
        *,
        doctor:users!appointments_doctor_id_fkey(id, full_name, email)
      `)
      .single();

    if (error) {
      logger.error('Appointment creation error:', error);
      return res.status(500).json({ error: 'Failed to create appointment' });
    }

    res.status(201).json({
      message: 'Appointment created successfully',
      appointment
    });

  } catch (error) {
    logger.error('Create appointment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's appointments
router.get('/', async (req, res) => {
  try {
    const { status, limit = 10, offset = 0 } = req.query;
    const supabase = getSupabaseClient();

    let query = supabase
      .from('appointments')
      .select(`
        *,
        doctor:users!appointments_doctor_id_fkey(id, full_name, email)
      `)
      .eq('user_id', req.user.id)
      .order('scheduled_at', { ascending: true })
      .range(offset, offset + limit - 1);

    if (status) {
      query = query.eq('status', status);
    }

    const { data: appointments, error } = await query;

    if (error) {
      logger.error('Get appointments error:', error);
      return res.status(500).json({ error: 'Failed to fetch appointments' });
    }

    res.json({ appointments });

  } catch (error) {
    logger.error('Get appointments error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update appointment status
router.patch('/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const supabase = getSupabaseClient();

    if (!['scheduled', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const { data: appointment, error } = await supabase
      .from('appointments')
      .update({ status })
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      logger.error('Update appointment error:', error);
      return res.status(500).json({ error: 'Failed to update appointment' });
    }

    if (!appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    res.json({
      message: 'Appointment status updated successfully',
      appointment
    });

  } catch (error) {
    logger.error('Update appointment status error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get available doctors
router.get('/doctors', async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: doctors, error } = await supabase
      .from('users')
      .select('id, full_name, email')
      .eq('role', 'doctor')
      .order('full_name', { ascending: true });

    if (error) {
      logger.error('Get doctors error:', error);
      return res.status(500).json({ error: 'Failed to fetch doctors' });
    }

    res.json({ doctors });

  } catch (error) {
    logger.error('Get doctors error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
