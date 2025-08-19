const express = require('express');
const { getSupabaseClient } = require('../config/database');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const twilio = require('twilio');

const router = express.Router();

// Initialize email and SMS services
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Input validation middleware
const validateContactInput = (req, res, next) => {
  const { name, phone_number } = req.body;
  
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Contact name is required' });
  }
  
  if (!phone_number || !phone_number.trim()) {
    return res.status(400).json({ error: 'Phone number is required' });
  }
  
  // Basic phone number validation
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  if (!phoneRegex.test(phone_number.replace(/[\s\-\(\)]/g, ''))) {
    return res.status(400).json({ error: 'Please enter a valid phone number' });
  }
  
  // Email validation if provided
  const { email } = req.body;
  if (email && email.trim()) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
  }
  
  next();
};

// Emergency Contacts Routes

// Get all emergency contacts for the user
router.get('/contacts', async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    const { data: contacts, error } = await supabase
      .from('emergency_contacts')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) {
      logger.error('Get emergency contacts error:', error);
      return res.status(500).json({ error: 'Failed to fetch emergency contacts' });
    }

    res.json({ contacts: contacts || [] });

  } catch (error) {
    logger.error('Get emergency contacts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add new emergency contact
router.post('/contacts', validateContactInput, async (req, res) => {
  try {
    const { name, phone_number, email, relationship } = req.body;
    const supabase = getSupabaseClient();

    // Check if user already has this contact (by phone number)
    const { data: existingContact, error: checkError } = await supabase
      .from('emergency_contacts')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('phone_number', phone_number.trim())
      .single();

    if (checkError && checkError.code !== 'PGRST116') {
      logger.error('Check existing contact error:', checkError);
      return res.status(500).json({ error: 'Failed to verify contact uniqueness' });
    }

    if (existingContact) {
      return res.status(409).json({ 
        error: 'A contact with this phone number already exists' 
      });
    }

    // Check contact limit (e.g., maximum 10 contacts)
    const { count, error: countError } = await supabase
      .from('emergency_contacts')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', req.user.id);

    if (countError) {
      logger.error('Count contacts error:', countError);
      return res.status(500).json({ error: 'Failed to verify contact limit' });
    }

    if (count >= 10) {
      return res.status(400).json({ 
        error: 'You can only have up to 10 emergency contacts' 
      });
    }

    const contactId = uuidv4();
    const contactData = {
      id: contactId,
      user_id: req.user.id,
      name: name.trim(),
      phone_number: phone_number.trim(),
      email: email ? email.trim() : null,
      relationship: relationship ? relationship.trim() : null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    const { data: contact, error } = await supabase
      .from('emergency_contacts')
      .insert([contactData])
      .select()
      .single();

    if (error) {
      logger.error('Create emergency contact error:', error);
      return res.status(500).json({ error: 'Failed to create emergency contact' });
    }

    logger.info(`Emergency contact created: ${contactId} for user: ${req.user.id}`);

    res.status(201).json({
      message: 'Emergency contact added successfully',
      contact
    });

  } catch (error) {
    logger.error('Create emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update emergency contact
router.put('/contacts/:id', validateContactInput, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone_number, email, relationship } = req.body;
    const supabase = getSupabaseClient();

    // Check if contact exists and belongs to user
    const { data: existingContact, error: fetchError } = await supabase
      .from('emergency_contacts')
      .select('*')
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (fetchError || !existingContact) {
      return res.status(404).json({ error: 'Emergency contact not found' });
    }

    // Check for duplicate phone number (excluding current contact)
    const { data: duplicateCheck, error: duplicateError } = await supabase
      .from('emergency_contacts')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('phone_number', phone_number.trim())
      .neq('id', id)
      .single();

    if (duplicateError && duplicateError.code !== 'PGRST116') {
      logger.error('Check duplicate contact error:', duplicateError);
      return res.status(500).json({ error: 'Failed to verify contact uniqueness' });
    }

    if (duplicateCheck) {
      return res.status(409).json({ 
        error: 'Another contact with this phone number already exists' 
      });
    }

    const updateData = {
      name: name.trim(),
      phone_number: phone_number.trim(),
      email: email ? email.trim() : null,
      relationship: relationship ? relationship.trim() : null,
      updated_at: new Date().toISOString()
    };

    const { data: contact, error } = await supabase
      .from('emergency_contacts')
      .update(updateData)
      .eq('id', id)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      logger.error('Update emergency contact error:', error);
      return res.status(500).json({ error: 'Failed to update emergency contact' });
    }

    logger.info(`Emergency contact updated: ${id} for user: ${req.user.id}`);

    res.json({
      message: 'Emergency contact updated successfully',
      contact
    });

  } catch (error) {
    logger.error('Update emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete emergency contact
router.delete('/contacts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const supabase = getSupabaseClient();

    // Check if contact exists and belongs to user
    const { data: existingContact, error: fetchError } = await supabase
      .from('emergency_contacts')
      .select('*')
      .eq('id', id)
      .eq('user_id', req.user.id)
      .single();

    if (fetchError || !existingContact) {
      return res.status(404).json({ error: 'Emergency contact not found' });
    }

    const { error } = await supabase
      .from('emergency_contacts')
      .delete()
      .eq('id', id)
      .eq('user_id', req.user.id);

    if (error) {
      logger.error('Delete emergency contact error:', error);
      return res.status(500).json({ error: 'Failed to delete emergency contact' });
    }

    logger.info(`Emergency contact deleted: ${id} for user: ${req.user.id}`);

    res.json({
      message: 'Emergency contact deleted successfully'
    });

  } catch (error) {
    logger.error('Delete emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Emergency Alert Routes (Enhanced)

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

// Enhanced emergency contact endpoint with better error handling
router.post('/contact', requireRole(['mother']), async (req, res) => {
  try {
    const { message, urgency } = req.body;
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: 'Emergency message is required' });
    }

    if (!['low', 'medium', 'high'].includes(urgency)) {
      return res.status(400).json({ error: 'Invalid urgency level' });
    }

    const supabase = getSupabaseClient();

    // Get user's emergency contacts
    const { data: contacts, error: contactsError } = await supabase
      .from('emergency_contacts')
      .select('*')
      .eq('user_id', req.user.id);

    if (contactsError) {
      logger.error('Fetch emergency contacts error:', contactsError);
      return res.status(500).json({ error: 'Failed to fetch emergency contacts' });
    }

    if (!contacts || contacts.length === 0) {
      return res.status(400).json({ 
        error: 'No emergency contacts found. Please add emergency contacts first.' 
      });
    }

    const alertId = uuidv4();
    const timestamp = new Date().toISOString();
    
    // Create emergency alert record
    const { error: alertError } = await supabase
      .from('emergency_alerts')
      .insert([{
        id: alertId,
        user_id: req.user.id,
        type: 'manual',
        message: message.trim(),
        urgency,
        triggered_at: timestamp,
        resolved: false
      }]);

    if (alertError) {
      logger.error('Create emergency alert error:', alertError);
      return res.status(500).json({ error: 'Failed to log emergency alert' });
    }

    const notificationPromises = [];
    const notificationResults = {
      email: { sent: 0, failed: 0 },
      sms: { sent: 0, failed: 0 }
    };

    // Send notifications to all contacts
    for (const contact of contacts) {
      // Send email notification
      if (contact.email) {
        const emailPromise = transporter.sendMail({
          to: contact.email,
          subject: `🚨 Emergency Alert from ${req.user.full_name}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <div style="background: linear-gradient(135deg, #FF8AB7, #FFB1CC); padding: 20px; text-align: center; color: white;">
                <h1 style="margin: 0; font-size: 24px;">🚨 Emergency Alert</h1>
              </div>
              <div style="padding: 20px; background: #fff;">
                <p><strong>From:</strong> ${req.user.full_name}</p>
                <p><strong>Urgency Level:</strong> <span style="color: ${urgency === 'high' ? '#D6336C' : urgency === 'medium' ? '#FF8AB7' : '#FFB1CC'}; font-weight: bold; text-transform: uppercase;">${urgency}</span></p>
                <p><strong>Message:</strong></p>
                <div style="background: #FFF0F5; padding: 15px; border-radius: 8px; border-left: 4px solid #FF8AB7;">
                  ${message.trim()}
                </div>
                <p><strong>Time:</strong> ${new Date(timestamp).toLocaleString()}</p>
                <p style="color: #D6336C; font-weight: bold;">Please contact ${req.user.full_name} immediately.</p>
              </div>
              <div style="padding: 15px; background: #FFF0F5; text-align: center; color: #FF8AB7;">
                <p style="margin: 0; font-size: 12px;">This is an automated emergency notification</p>
              </div>
            </div>
          `,
        }).then(() => {
          notificationResults.email.sent++;
        }).catch((error) => {
          logger.error(`Email notification failed for ${contact.email}:`, error);
          notificationResults.email.failed++;
        });

        notificationPromises.push(emailPromise);
      }

      // Send SMS notification
      if (contact.phone_number) {
        const smsMessage = `🚨 EMERGENCY ALERT from ${req.user.full_name}\n\nUrgency: ${urgency.toUpperCase()}\n\nMessage: ${message.trim()}\n\nTime: ${new Date(timestamp).toLocaleString()}\n\nPlease contact ${req.user.full_name} immediately!`;

        const smsPromise = twilioClient.messages.create({
          body: smsMessage,
          from: process.env.TWILIO_PHONE_NUMBER,
          to: contact.phone_number,
        }).then(() => {
          notificationResults.sms.sent++;
        }).catch((error) => {
          logger.error(`SMS notification failed for ${contact.phone_number}:`, error);
          notificationResults.sms.failed++;
        });

        notificationPromises.push(smsPromise);
      }
    }

    // Wait for all notifications to complete
    await Promise.allSettled(notificationPromises);

    logger.info(`Emergency alert ${alertId} sent to ${contacts.length} contacts. Email: ${notificationResults.email.sent} sent, ${notificationResults.email.failed} failed. SMS: ${notificationResults.sms.sent} sent, ${notificationResults.sms.failed} failed.`);

    const totalSent = notificationResults.email.sent + notificationResults.sms.sent;
    const totalFailed = notificationResults.email.failed + notificationResults.sms.failed;

    res.json({
      message: 'Emergency alert processed',
      alert_id: alertId,
      timestamp: timestamp,
      notifications: {
        total_contacts: contacts.length,
        notifications_sent: totalSent,
        notifications_failed: totalFailed,
        details: notificationResults
      }
    });

  } catch (error) {
    logger.error('Emergency contact error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Quick call emergency service (for future expansion)
router.post('/emergency-call', requireRole(['mother']), async (req, res) => {
  try {
    const { service_type = 'general' } = req.body;
    const supabase = getSupabaseClient();

    // Log the emergency call request
    const callId = uuidv4();
    await supabase
      .from('emergency_calls')
      .insert([{
        id: callId,
        user_id: req.user.id,
        service_type,
        requested_at: new Date().toISOString(),
        status: 'requested'
      }]);

    // In a real implementation, this would integrate with emergency services
    // For now, we'll just log and return emergency numbers

    const emergencyNumbers = {
      general: '911',
      police: '911',
      fire: '911',
      medical: '911',
      poison_control: '1-800-222-1222'
    };

    res.json({
      message: 'Emergency service contact initiated',
      call_id: callId,
      emergency_number: emergencyNumbers[service_type] || '911',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Emergency call error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;