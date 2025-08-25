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
    const { doctor_id, appointment_date, time, notes, type } = req.body;
    const supabase = getSupabaseClient();

    // Verify doctor exists in the doctors table
    const { data: doctor, error: doctorError } = await supabase
      .from('doctors')
      .select('id, name, specialty')
      .eq('id', doctor_id)
      .single();

    if (doctorError || !doctor) {
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
        appointment_date,
        time,
        status: 'scheduled',
        notes
      }])
      .select(`
        *,
        doctors!appointments_doctor_id_fkey(id, name, specialty)
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
        doctors!appointments_doctor_id_fkey(id, name, specialty)
      `)
      .eq('user_id', req.user.id)
      .order('appointment_date', { ascending: true })
      .range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

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

    // Check if appointment exists and belongs to user first
    const { data: existingAppointment } = await supabase
      .from('appointments')
      .select('id')
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (!existingAppointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    const { data: appointment, error } = await supabase
      .from('appointments')
      .update({ status })
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select(`
        *,
        doctors!appointments_doctor_id_fkey(id, name, specialty)
      `)
      .single();

    if (error) {
      logger.error('Update appointment error:', error);
      return res.status(500).json({ error: 'Failed to update appointment' });
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
      .from('doctors')
      .select('id, name, specialty, experience, rating, image, nextavailable, consultationfee, languages')
      .order('name', { ascending: true });

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

// Get single appointment details
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const supabase = getSupabaseClient();

    const { data: appointment, error } = await supabase
      .from('appointments')
      .select(`
        *,
        doctors!appointments_doctor_id_fkey(id, name, specialty, experience, rating)
      `)
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (error || !appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    res.json({ appointment });

  } catch (error) {
    logger.error('Get appointment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete appointment
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const supabase = getSupabaseClient();

    // Check if appointment exists and belongs to user
    const { data: existingAppointment } = await supabase
      .from('appointments')
      .select('id, status')
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (!existingAppointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    // Prevent deletion of completed appointments
    if (existingAppointment.status === 'completed') {
      return res.status(400).json({ error: 'Cannot delete completed appointments' });
    }

    const { error } = await supabase
      .from('appointments')
      .delete()
      .eq('id', id)
      .eq('user_id', req.user.id);

    if (error) {
      logger.error('Delete appointment error:', error);
      return res.status(500).json({ error: 'Failed to delete appointment' });
    }

    res.json({ message: 'Appointment deleted successfully' });

  } catch (error) {
    logger.error('Delete appointment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;