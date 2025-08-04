const express = require('express');
const { getSupabaseClient } = require('../config/database');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Get emergency alerts
router.get('/alerts', async (req, res) => {
  try {
    const { resolved, limit = 10, offset = 0 } = req.query;
    const supabase = getSupabaseClient();

    let query = supabase
      .from('emergency_alerts')
      .select('*')
      .eq('user_id', req.user.id)
      .order('triggered_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (resolved !== undefined) {
      query = query.eq('resolved', resolved === 'true');
    }

    const { data: alerts, error } = await query;

    if (error) {
      logger.error('Get emergency alerts error:', error);
      return res.status(500).json({ error: 'Failed to fetch emergency alerts' });
    }

    res.json({ alerts });

  } catch (error) {
    logger.error('Get emergency alerts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Mark alert as resolved
router.patch('/alerts/:id/resolve', async (req, res) => {
  try {
    const { id } = req.params;
    const supabase = getSupabaseClient();

    const { data: alert, error } = await supabase
      .from('emergency_alerts')
      .update({
        resolved: true,
        resolved_at: new Date().toISOString()
      })
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      logger.error('Resolve alert error:', error);
      return res.status(500).json({ error: 'Failed to resolve alert' });
    }

    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    res.json({
      message: 'Alert resolved successfully',
      alert
    });

  } catch (error) {
    logger.error('Resolve alert error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Emergency contact endpoint

router.post('/contact', requireRole(['mother']), async (req, res) => {
  try {
    const { message, urgency } = req.body;
    const supabase = getSupabaseClient();

    // Get user's emergency contacts
    const { data: contacts, error: contactsError } = await supabase
      .from('emergency_contacts')
      .select('name, email, phone_number')
      .eq('user_id', req.user.id);

    if (contactsError) {
      logger.error('Fetch emergency contacts error:', contactsError);
      return res.status(500).json({ error: 'Failed to fetch emergency contacts' });
    }

    // Send notifications
    for (const contact of contacts) {
      if (contact.email) {
        await transporter.sendMail({
          to: contact.email,
          subject: `Emergency Alert from ${req.user.full_name}`,
          text: `Urgency: ${urgency}\nMessage: ${message}\nPlease contact ${req.user.full_name} immediately.`,
        });
      }
      if (contact.phone_number) {
        await client.messages.create({
          body: `Emergency from ${req.user.full_name}: ${message} (Urgency: ${urgency})`,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: contact.phone_number,
        });
      }
    }

    // Log emergency event
    const alertId = uuidv4();
    await supabase
      .from('emergency_alerts')
      .insert([{
        id: alertId,
        user_id: req.user.id,
        type: 'manual',
        message,
        urgency,
        triggered_at: new Date().toISOString(),
        resolved: false
      }]);

    res.json({
      message: 'Emergency services and contacts notified',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
