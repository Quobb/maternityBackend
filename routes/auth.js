const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { validateRegistration, validateLogin } = require('../middleware/validation');
const logger = require('../utils/logger');
const nodemailer = require('nodemailer');
const twilio = require('twilio');

const { authenticateToken } = require('../middleware/auth');

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);


const router = express.Router();

// Register
router.post('/register', validateRegistration, async (req, res) => {
  try {
    const { email, password, full_name, phone_number, role, date_of_birth } = req.body;
    const supabase = getSupabaseClient();

    // Check if user exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const password_hash = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = uuidv4();
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        id: userId,
        email,
        password_hash,
        full_name,
        phone_number,
        role,
        date_of_birth,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select()
      .single();

    if (error) {
      logger.error('User creation error:', error);
      return res.status(500).json({ error: 'Failed to create user' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    // Remove password hash from response
    const { password_hash: _, ...userResponse } = user;

    res.status(201).json({
      message: 'User created successfully',
      user: userResponse,
      token
    });

  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;
    const supabase = getSupabaseClient();

    // Find user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    // Update last login
    await supabase
      .from('users')
      .update({ updated_at: new Date().toISOString() })
      .eq('id', user.id);

    // Remove password hash from response
    const { password_hash: _, ...userResponse } = user;

    res.json({
      message: 'Login successful',
      user: userResponse,
      token
    });

  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const supabase = getSupabaseClient();

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, full_name, phone_number, role, date_of_birth, created_at, updated_at')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    res.json({ user });

  } catch (error) {
    logger.error('Get user error:', error);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
});

// routes/auth.js (Add to existing file)
router.delete('/me', authenticateToken, async (req, res) => {
  try {
    const supabase = getSupabaseClient();

    // Soft delete user and related data
    const { error } = await supabase
      .from('users')
      .update({ deleted_at: new Date().toISOString(), email: null, phone_number: null })
      .eq('id', req.user.id);

    if (error) {
      logger.error('User deletion error:', error);
      return res.status(500).json({ error: 'Failed to delete user data' });
    }

    // Log deletion for audit
    logger.info(`User ${req.user.id} requested data deletion`);

    res.json({ message: 'User data deleted successfully' });
  } catch (error) {
    logger.error('User deletion error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password Reset Request
router.post('/password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    const supabase = getSupabaseClient();

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600 * 1000); // 1 hour expiry

    await supabase
      .from('password_resets')
      .insert([{ user_id: user.id, token: resetToken, expires_at: expiresAt.toISOString() }]);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
JWT_SECRET
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset Request',
      text: `Use this link to reset your password: ${process.env.FRONTEND_URL}/reset-password/${resetToken}`,
    });

    res.json({ message: 'Password reset link sent' });
  } catch (error) {
    logger.error('Password reset error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify Password Reset Token
router.post('/password-reset/verify', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const supabase = getSupabaseClient();

    const { data: reset, error } = await supabase
      .from('password_resets')
      .select('user_id, expires_at')
      .eq('token', token)
      .single();

    if (error || !reset || new Date(reset.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const password_hash = await bcrypt.hash(newPassword, 12);
    await supabase
      .from('users')
      .update({ password_hash, updated_at: new Date().toISOString() })
      .eq('id', reset.user_id);

    await supabase.from('password_resets').delete().eq('token', token);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    logger.error('Password reset verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Enable 2FA
router.post('/enable-2fa', authenticateToken, async (req, res) => {
  try {
    const { phone_number } = req.body;
    const supabase = getSupabaseClient();

    const verification = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SID)
      .verifications.create({ to: phone_number, channel: 'sms' });

    await supabase
      .from('users')
      .update({ phone_number, two_factor_enabled: true })
      .eq('id', req.user.id);

    res.json({ message: '2FA enabled, verification code sent' });
  } catch (error) {
    logger.error('Enable 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify 2FA Code
router.post('/verify-2fa', async (req, res) => {
  try {
    const { phone_number, code } = req.body;

    const verificationCheck = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SID)
      .verificationChecks.create({ to: phone_number, code });

    if (verificationCheck.status !== 'approved') {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    res.json({ message: '2FA verification successful' });
  } catch (error) {
    logger.error('Verify 2FA error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
