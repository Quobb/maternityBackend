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

// Helper function to validate environment variables
const validateEnvVars = () => {
  const required = ['JWT_SECRET', 'SUPABASE_URL', 'SUPABASE_ANON_KEY'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
};

// Register
router.post('/register', validateRegistration, async (req, res) => {
  try {
    validateEnvVars();
    
    const { email, password, full_name, phone_number, role, date_of_birth } = req.body;
    const supabase = getSupabaseClient();

    // Check if user exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .maybeSingle();

    if (checkError) {
      logger.error('Database check error:', checkError);
      return res.status(500).json({ error: 'Database error' });
    }

    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const password_hash = await bcrypt.hash(password, saltRounds);

    // Create user
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        email,
        password_hash,
        full_name,
        phone_number,
        role: role || 'patient',
        date_of_birth,
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
    validateEnvVars();
    
    const { email, password } = req.body;
    const supabase = getSupabaseClient();

    // Find user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .maybeSingle();

    if (error) {
      logger.error('Database error during login:', error);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
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
router.get('/me', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user.id) {
      logger.error('Invalid or missing user id in request');
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    const supabase = getSupabaseClient();

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, full_name, phone_number, role, date_of_birth, created_at, updated_at, two_factor_enabled')
      .eq('id', req.user.id.toString())
      .is('deleted_at', null)
      .single();

    if (error || !user) {
      logger.error(`Get user error for id ${req.user.id}:`, error);
      return res.status(401).json({ error: 'User not found' });
    }

    res.json({ user });

  } catch (error) {
    logger.error(`Get user error for id ${req.user.id || 'unknown'}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user.id) {
      logger.error('Invalid or missing user id in request');
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    // Log user ID for debugging
    logger.info(`Fetching profile for id: ${req.user.id}`);

    const supabase = getSupabaseClient();

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, full_name, phone_number, role, date_of_birth, created_at, updated_at, two_factor_enabled, profile_image')
      .eq('id', req.user.id.toString())
      .is('deleted_at', null)
      .single();

    if (error || !user) {
      logger.error(`Get profile error for id ${req.user.id}:`, error);
      return res.status(401).json({ error: 'User not found' });
    }

    res.json({
      message: 'Profile retrieved successfully',
      user
    });

  } catch (error) {
    logger.error(`Get profile error for id ${req.user.id || 'unknown'}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
router.patch('/profile', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user.id) {
      logger.error('Invalid or missing user id in request');
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    // Log user ID for debugging
    logger.info(`Updating profile for id: ${req.user.id}`);

    const { name, email, phone, profile_image } = req.body;
    const supabase = getSupabaseClient();

    // Validate input
    if (!name && !email && !phone && !profile_image) {
      return res.status(400).json({ error: 'At least one field must be provided for update' });
    }

    // Check if email is already in use by another user
    if (email) {
      const { data: existingUser, error: checkError } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .neq('id', req.user.id.toString())
        .maybeSingle();

      if (checkError) {
        logger.error(`Email check error for id ${req.user.id}:`, checkError);
        return res.status(500).json({ error: 'Database error' });
      }

      if (existingUser) {
        return res.status(409).json({ error: 'Email already in use' });
      }
    }

    // Prepare update object
    const updateData = {};
    if (name) updateData.full_name = name;
    if (email) updateData.email = email;
    if (phone) updateData.phone_number = phone;
    if (profile_image) updateData.profile_image = profile_image;
    updateData.updated_at = new Date().toISOString();

    // Update user in database
    const { data: updatedUser, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', req.user.id.toString())
      .select('id, email, full_name, phone_number, role, date_of_birth, created_at, updated_at, two_factor_enabled, profile_image')
      .single();

    if (error) {
      logger.error(`Profile update error for id ${req.user.id}:`, error);
      return res.status(500).json({ error: 'Failed to update profile' });
    }

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });

  } catch (error) {
    logger.error(`Profile update error for id ${req.user.id || 'unknown'}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user account (soft delete)
router.delete('/me', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user.id) {
      logger.error('Invalid or missing user id in request');
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    const supabase = getSupabaseClient();

    // Soft delete user
    const { error } = await supabase
      .from('users')
      .update({ 
        deleted_at: new Date().toISOString(), 
        email: null, 
        phone_number: null 
      })
      .eq('id', req.user.id.toString());

    if (error) {
      logger.error(`User deletion error for id ${req.user.id}:`, error);
      return res.status(500).json({ error: 'Failed to delete user data' });
    }

    // Log deletion for audit
    logger.info(`User ${req.user.id} requested data deletion`);

    res.json({ message: 'User data deleted successfully' });
  } catch (error) {
    logger.error(`User deletion error for id ${req.user.id || 'unknown'}:`, error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Password Reset Request
router.post('/password-reset', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const supabase = getSupabaseClient();

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email')
      .eq('email', email)
      .is('deleted_at', null)
      .maybeSingle();

    if (error) {
      logger.error('Database error during password reset:', error);
      return res.status(500).json({ error: 'Database error' });
    }

    // Always return success to prevent email enumeration
    if (!user) {
      return res.json({ message: 'If an account exists, password reset link has been sent' });
    }

    const resetToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600 * 1000); // 1 hour expiry

    // Delete any existing reset tokens for this user
    await supabase
      .from('password_resets')
      .delete()
      .eq('user_id', user.id);

    // Insert new reset token
    const { error: insertError } = await supabase
      .from('password_resets')
      .insert([{ 
        user_id: user.id, 
        token: resetToken, 
        expires_at: expiresAt.toISOString() 
      }]);

    if (insertError) {
      logger.error('Error creating password reset token:', insertError);
      return res.status(500).json({ error: 'Failed to create reset token' });
    }

    // Send email (only if environment variables are set)
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
          },
        });

        await transporter.sendMail({
          to: email,
          subject: 'Password Reset Request',
          html: `
            <h2>Password Reset Request</h2>
            <p>Click the link below to reset your password:</p>
            <a href="${process.env.FRONTEND_URL}/reset-password/${resetToken}">Reset Password</a>
            <p>This link expires in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
          `,
        });
      } catch (emailError) {
        logger.error('Email sending error:', emailError);
        // Don't fail the request if email fails
      }
    }

    res.json({ message: 'If an account exists, password reset link has been sent' });
  } catch (error) {
    logger.error('Password reset error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify Password Reset Token
router.post('/password-reset/verify', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    const supabase = getSupabaseClient();

    const { data: reset, error } = await supabase
      .from('password_resets')
      .select('user_id, expires_at')
      .eq('token', token)
      .maybeSingle();

    if (error) {
      logger.error('Database error during password reset verification:', error);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!reset || new Date(reset.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const password_hash = await bcrypt.hash(newPassword, 12);
    
    const { error: updateError } = await supabase
      .from('users')
      .update({ password_hash, updated_at: new Date().toISOString() })
      .eq('id', reset.user_id);

    if (error) {
      logger.error('Error updating password:', updateError);
      return res.status(500).json({ error: 'Failed to update password' });
    }

    // Delete the used reset token
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

    if (!phone_number) {
      return res.status(400).json({ error: 'Phone number is required' });
    }

    if (!process.env.TWILIO_VERIFY_SID) {
      return res.status(500).json({ error: '2FA service not configured' });
    }

    const supabase = getSupabaseClient();

    const verification = await client.verify.v2
      .services(process.env.TWILIO_VERIFY_SID)
      .verifications.create({ to: phone_number, channel: 'sms' });

    const { error } = await supabase
      .from('users')
      .update({ phone_number, two_factor_enabled: true })
      .eq('id', req.user.id);

    if (error) {
      logger.error('Error enabling 2FA:', error);
      return res.status(500).json({ error: 'Failed to enable 2FA' });
    }

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

    if (!phone_number || !code) {
      return res.status(400).json({ error: 'Phone number and code are required' });
    }

    if (!process.env.TWILIO_VERIFY_SID) {
      return res.status(500).json({ error: '2FA service not configured' });
    }

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