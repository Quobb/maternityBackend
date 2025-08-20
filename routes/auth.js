const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { body, param, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { getSupabaseClient } = require('../config/database');
const { validateRegistration, validateLogin } = require('../middleware/validation');
const { authenticateToken } = require('../middleware/auth');
const logger = require('../utils/logger');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const cloudinary = require('cloudinary').v2;

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
const router = express.Router();

// Constants
const SALT_ROUNDS = 12;
const PASSWORD_MIN_LENGTH = 8;
const OTP_EXPIRY_MINUTES = 10;
const RESET_TOKEN_EXPIRY_HOURS = 1;
const MAX_FAILED_ATTEMPTS = 100;
const LOCKOUT_DURATION_MINUTES = 15;
const PHONE_REGEX = /^\+?[1-9]\d{1,14}$/;

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});



const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // 3 OTP requests per window per IP
  message: { error: 'Too many OTP requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});



// Helper function to validate environment variables
const validateEnvVars = () => {
  const required = [
    'JWT_SECRET',
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'CLOUDINARY_CLOUD_NAME',
    'CLOUDINARY_API_KEY',
    'CLOUDINARY_API_SECRET'
  ];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
};

// Standardized response helper
const sendResponse = (res, status, message, data = null, errors = null) => {
  return res.status(status).json({
    success: status < 400,
    message,
    data,
    errors,
    timestamp: new Date().toISOString()
  });
};

// Helper function to generate secure token
const generateSecureToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Helper function to check account lockout
const checkAccountLockout = async (supabase, email) => {
  const { data: attempts, error } = await supabase
    .from('failed_login_attempts')
    .select('*')
    .eq('email', email)
    .gte('created_at', new Date(Date.now() - LOCKOUT_DURATION_MINUTES * 60 * 1000).toISOString())
    .order('created_at', { ascending: false });

  if (error) {
    logger.error('Failed login attempts check error:', error);
    return { isLocked: false, attempts: 0 };
  }

  const recentAttempts = attempts?.length || 0;
  const isLocked = recentAttempts >= MAX_FAILED_ATTEMPTS;
  
  return { isLocked, attempts: recentAttempts };
};

// Helper function to record failed login attempt
const recordFailedAttempt = async (supabase, email, ip) => {
  try {
    await supabase
      .from('failed_login_attempts')
      .insert([{ email, ip_address: ip }]);
  } catch (error) {
    logger.error('Failed to record login attempt:', error);
  }
};

// Helper function to clear failed login attempts
const clearFailedAttempts = async (supabase, email) => {
  try {
    await supabase
      .from('failed_login_attempts')
      .delete()
      .eq('email', email);
  } catch (error) {
    logger.error('Failed to clear login attempts:', error);
  }
};

// Validation middleware for profile creation
const validateProfileCreation = [
  body('age')
    .optional()
    .isInt({ min: 0, max: 120 })
    .withMessage('Age must be a valid integer between 0 and 120'),
  body('bmi')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 50 })
    .withMessage('BMI must be a string with max 50 characters'),
  body('medical_conditions')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Medical conditions must be a string with max 1000 characters'),
  body('previous_pregnancies')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Previous pregnancies must be a string with max 500 characters'),
  body('gestational_week')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 50 })
    .withMessage('Gestational week must be a string with max 50 characters'),
  body('weight')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Weight must be a positive number')
];

// Validation middleware for profile update
const validateProfileUpdate = [
  param('id').isInt().withMessage('Profile ID must be a valid integer'),
  ...validateProfileCreation
];

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return sendResponse(res, 400, 'Validation failed', null, errors.array());
  }
  next();
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
      return sendResponse(res, 500, 'Database error');
    }

    if (existingUser) {
      return sendResponse(res, 409, 'User already exists');
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

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
      return sendResponse(res, 500, 'Failed to create user');
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    // Remove password hash from response
    const { password_hash: _, ...userResponse } = user;

    logger.info(`User registered successfully: ${user.id}`);

    return sendResponse(res, 201, 'User created successfully', {
      user: userResponse,
      token
    });

  } catch (error) {
    logger.error('Registration error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Login
router.post('/login', validateLogin, async (req, res) => {
  try {
    validateEnvVars();
    
    const { email, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    const supabase = getSupabaseClient();

    // Check account lockout
    const { isLocked, attempts } = await checkAccountLockout(supabase, email);
    if (isLocked) {
      logger.warn(`Account locked due to failed attempts: ${email}`);
      return sendResponse(res, 429, 'Account temporarily locked due to multiple failed attempts');
    }

    // Find user
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .is('deleted_at', null)
      .maybeSingle();

    if (error) {
      logger.error('Database error during login:', error);
      return sendResponse(res, 500, 'Database error');
    }

    if (!user) {
      await recordFailedAttempt(supabase, email, clientIP);
      return sendResponse(res, 401, 'Invalid credentials');
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      await recordFailedAttempt(supabase, email, clientIP);
      logger.warn(`Failed login attempt for user: ${email}`);
      return sendResponse(res, 401, 'Invalid credentials');
    }

    // Clear failed attempts on successful login
    await clearFailedAttempts(supabase, email);

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

    logger.info(`Successful login: ${user.id}`);

    return sendResponse(res, 200, 'Login successful', {
      user: userResponse,
      token
    });

  } catch (error) {
    logger.error('Login error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Get current user
router.get('/me', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user?.id) {
      logger.error('Invalid or missing user id in request');
      return sendResponse(res, 401, 'Invalid authentication token');
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
      return sendResponse(res, 401, 'User not found');
    }

    return sendResponse(res, 200, 'User retrieved successfully', { user });

  } catch (error) {
    logger.error(`Get user error for id ${req.user?.id || 'unknown'}:`, error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user?.id) {
      logger.error('Invalid or missing user id in request');
      return sendResponse(res, 401, 'Invalid authentication token');
    }

    const supabase = getSupabaseClient();

    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, full_name, phone_number, role, date_of_birth, created_at, updated_at, two_factor_enabled, profile_image')
      .eq('id', req.user.id.toString())
      .is('deleted_at', null)
      .single();

    if (error || !user) {
      logger.error(`Get profile error for id ${req.user.id}:`, error);
      return sendResponse(res, 401, 'User not found');
    }

    return sendResponse(res, 200, 'Profile retrieved successfully', { user });

  } catch (error) {
    logger.error(`Get profile error for id ${req.user?.id || 'unknown'}:`, error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Update user profile
router.patch('/profile', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user?.id) {
      logger.error('Invalid or missing user id in request');
      return sendResponse(res, 401, 'Invalid authentication token');
    }

    const { name, email, phone, profile_image } = req.body;
    const supabase = getSupabaseClient();

    // Validate input
    if (!name && !email && !phone && !profile_image) {
      return sendResponse(res, 400, 'At least one field must be provided for update');
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
        return sendResponse(res, 500, 'Database error');
      }

      if (existingUser) {
        return sendResponse(res, 409, 'Email already in use');
      }
    }

    // Prepare update object
    const updateData = {};
    if (name) updateData.full_name = name;
    if (email) updateData.email = email;
    if (phone) updateData.phone_number = phone;

    // Handle profile image upload to Cloudinary
    if (profile_image) {
      try {
        const uploadResult = await cloudinary.uploader.upload(profile_image, {
          folder: 'profile_images',
          resource_type: 'image',
          transformation: [{ width: 200, height: 200, crop: 'fill' }],
        });
        updateData.profile_image = uploadResult.secure_url;
      } catch (uploadError) {
        logger.error(`Cloudinary upload error for id ${req.user.id}:`, uploadError);
        return sendResponse(res, 500, 'Failed to upload profile image');
      }
    }

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
      return sendResponse(res, 500, 'Failed to update profile');
    }

    logger.info(`Profile updated for user: ${req.user.id}`);

    return sendResponse(res, 200, 'Profile updated successfully', { user: updatedUser });

  } catch (error) {
    logger.error(`Profile update error for id ${req.user?.id || 'unknown'}:`, error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Delete user account (soft delete)
router.delete('/me', authenticateToken, async (req, res) => {
  try {
    // Validate user ID
    if (!req.user?.id) {
      logger.error('Invalid or missing user id in request');
      return sendResponse(res, 401, 'Invalid authentication token');
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
      return sendResponse(res, 500, 'Failed to delete user data');
    }

    // Log deletion for audit
    logger.info(`User ${req.user.id} requested data deletion`);

    return sendResponse(res, 200, 'User data deleted successfully');
  } catch (error) {
    logger.error(`User deletion error for id ${req.user?.id || 'unknown'}:`, error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Password Reset Request
router.post('/password-reset', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return sendResponse(res, 400, 'Email is required');
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
      return sendResponse(res, 500, 'Database error');
    }

    // Always return success to prevent email enumeration
    if (!user) {
      return sendResponse(res, 200, 'If an account exists, password reset link has been sent');
    }

    const resetToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + RESET_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);

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
      return sendResponse(res, 500, 'Failed to create reset token');
    }

    // Send email (only if environment variables are set)
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      try {
        const transporter = nodemailer.createTransporter({
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
            <p>This link expires in ${RESET_TOKEN_EXPIRY_HOURS} hour(s).</p>
            <p>If you didn't request this, please ignore this email.</p>
          `,
        });

        logger.info(`Password reset email sent to: ${email}`);
      } catch (emailError) {
        logger.error('Email sending error:', emailError);
        // Don't fail the request if email fails
      }
    }

    return sendResponse(res, 200, 'If an account exists, password reset link has been sent');
  } catch (error) {
    logger.error('Password reset error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Verify Password Reset Token
router.post('/password-reset/verify', async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return sendResponse(res, 400, 'Token and new password are required');
    }

    if (newPassword.length < PASSWORD_MIN_LENGTH) {
      return sendResponse(res, 400, `Password must be at least ${PASSWORD_MIN_LENGTH} characters long`);
    }

    const supabase = getSupabaseClient();

    const { data: reset, error } = await supabase
      .from('password_resets')
      .select('user_id, expires_at')
      .eq('token', token)
      .maybeSingle();

    if (error) {
      logger.error('Database error during password reset verification:', error);
      return sendResponse(res, 500, 'Database error');
    }

    if (!reset || new Date(reset.expires_at) < new Date()) {
      return sendResponse(res, 400, 'Invalid or expired token');
    }

    const password_hash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    const { error: updateError } = await supabase
      .from('users')
      .update({ password_hash, updated_at: new Date().toISOString() })
      .eq('id', reset.user_id);

    if (updateError) {
      logger.error('Error updating password:', updateError);
      return sendResponse(res, 500, 'Failed to update password');
    }

    // Delete the used reset token
    await supabase.from('password_resets').delete().eq('token', token);

    logger.info(`Password reset successful for user: ${reset.user_id}`);

    return sendResponse(res, 200, 'Password reset successfully');
  } catch (error) {
    logger.error('Password reset verification error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Enable 2FA
router.post('/enable-2fa', authenticateToken, async (req, res) => {
  try {
    const { phone_number } = req.body;

    if (!phone_number) {
      return sendResponse(res, 400, 'Phone number is required');
    }

    if (!PHONE_REGEX.test(phone_number)) {
      return sendResponse(res, 400, 'Invalid phone number format');
    }

    if (!process.env.TWILIO_VERIFY_SID) {
      return sendResponse(res, 500, '2FA service not configured');
    }

    const supabase = getSupabaseClient();

    try {
      const verification = await client.verify.v2
        .services(process.env.TWILIO_VERIFY_SID)
        .verifications.create({ 
          to: phone_number, 
          channel: 'sms',
          customFriendlyName: 'Healthcare App 2FA Setup'
        });

      const { error } = await supabase
        .from('users')
        .update({ phone_number, two_factor_enabled: true })
        .eq('id', req.user.id);

      if (error) {
        logger.error('Error enabling 2FA:', error);
        return sendResponse(res, 500, 'Failed to enable 2FA');
      }

      logger.info(`2FA enabled for user: ${req.user.id}`);

      return sendResponse(res, 200, '2FA enabled, verification code sent');
    } catch (twilioError) {
      logger.error('Twilio 2FA error:', twilioError);
      return sendResponse(res, 500, 'Failed to send verification code');
    }
  } catch (error) {
    logger.error('Enable 2FA error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Verify 2FA Code
router.post('/verify-2fa', otpLimiter, async (req, res) => {
  try {
    const { phone_number, code } = req.body;

    if (!phone_number || !code) {
      return sendResponse(res, 400, 'Phone number and code are required');
    }

    if (!process.env.TWILIO_VERIFY_SID) {
      return sendResponse(res, 500, '2FA service not configured');
    }

    try {
      const verificationCheck = await client.verify.v2
        .services(process.env.TWILIO_VERIFY_SID)
        .verificationChecks.create({ to: phone_number, code });

      if (verificationCheck.status !== 'approved') {
        return sendResponse(res, 400, 'Invalid verification code');
      }

      logger.info(`2FA verification successful for phone: ${phone_number}`);

      return sendResponse(res, 200, '2FA verification successful');
    } catch (twilioError) {
      logger.error('Twilio verify 2FA error:', twilioError);
      return sendResponse(res, 400, 'Invalid verification code');
    }
  } catch (error) {
    logger.error('Verify 2FA error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Phone Login - Step 1: Send OTP
router.post('/phone-login', otpLimiter, async (req, res) => {
  try {
    const { phone_number, role } = req.body;

    // Validate phone number
    if (!phone_number) {
      return sendResponse(res, 400, 'Phone number is required');
    }

    if (!PHONE_REGEX.test(phone_number)) {
      return sendResponse(res, 400, 'Invalid phone number format');
    }

    // Check Twilio env
    if (!process.env.TWILIO_VERIFY_SID || !process.env.TWILIO_SID || !process.env.TWILIO_AUTH_TOKEN) {
      logger.error('Twilio credentials missing');
      return sendResponse(res, 500, 'Phone authentication service not available');
    }

    const supabase = getSupabaseClient();

    // Find user
    const { data: user, error } = await supabase
      .from('users')
      .select('id, phone_number, role, full_name, email, two_factor_enabled')
      .eq('phone_number', phone_number)
      .is('deleted_at', null)
      .maybeSingle();

    if (error) {
      logger.error('Supabase user lookup error:', error);
      return sendResponse(res, 500, 'Database error');
    }

    if (!user) {
      return sendResponse(res, 404, 'No account found with this phone number');
    }

    // Optional role check
    if (role && user.role !== role) {
      return sendResponse(res, 401, 'Invalid credentials for this role');
    }

    // Send OTP
    try {
      const verification = await client.verify.v2
        .services(process.env.TWILIO_VERIFY_SID)
        .verifications.create({
          to: phone_number,
          channel: 'sms',
          customFriendlyName: 'Healthcare App Login'
        });

      logger.info(`OTP sent to ${phone_number} (user_id: ${user.id})`);

      // Generate session token
      const sessionToken = uuidv4();
      const expiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

      // Clean up old sessions
      await supabase
        .from('phone_login_sessions')
        .delete()
        .eq('user_id', user.id);

      // Create new session
      const { error: sessionError } = await supabase
        .from('phone_login_sessions')
        .insert([{
          user_id: user.id,
          session_token: sessionToken,
          phone_number,
          expires_at: expiresAt.toISOString(),
          verified: false
        }]);

      if (sessionError) {
        logger.error('Failed to create session:', sessionError);
        return sendResponse(res, 500, 'Login session creation failed');
      }

      return sendResponse(res, 200, 'OTP sent successfully', {
        sessionToken,
        expiresIn: OTP_EXPIRY_MINUTES * 60, // seconds
        phone_number: phone_number.replace(/(\+\d{3})(\d{3})(\d{4})/, '$1****$3') // Masked
      });

    } catch (twilioError) {
      logger.error('Twilio Verify error:', twilioError);

      if (twilioError.code === 60200) {
        return sendResponse(res, 400, 'Invalid phone number');
      } else if (twilioError.code === 60203) {
        return sendResponse(res, 429, 'Too many attempts. Try again later.');
      }

      return sendResponse(res, 500, 'Failed to send OTP. Please try again.');
    }

  } catch (err) {
    logger.error('Unhandled phone login error:', err);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Phone Login - Step 2: Verify OTP and Complete Login
router.post('/verify-phone-otp', otpLimiter, async (req, res) => {
  try {
    const { sessionToken, otpCode } = req.body;

    // Validate input
    if (!sessionToken || !otpCode) {
      return sendResponse(res, 400, 'Session token and OTP code are required');
    }

    // Validate OTP code format
    if (!/^\d{6}$/.test(otpCode)) {
      return sendResponse(res, 400, 'Invalid OTP format. Please enter a 6-digit code.');
    }

    const supabase = getSupabaseClient();

    // Get session data
    const { data: session, error: sessionError } = await supabase
      .from('phone_login_sessions')
      .select('user_id, phone_number, expires_at, verified')
      .eq('session_token', sessionToken)
      .maybeSingle();

    if (sessionError) {
      logger.error('Database error during OTP verification:', sessionError);
      return sendResponse(res, 500, 'Database error');
    }

    if (!session) {
      return sendResponse(res, 400, 'Invalid or expired session');
    }

    if (new Date(session.expires_at) < new Date()) {
      // Clean up expired session
      await supabase
        .from('phone_login_sessions')
        .delete()
        .eq('session_token', sessionToken);
      
      return sendResponse(res, 400, 'Session expired. Please request a new OTP.');
    }

    if (session.verified) {
      return sendResponse(res, 400, 'OTP already verified. Please login again.');
    }

    try {
      // Verify OTP with Twilio
      const verificationCheck = await client.verify.v2
        .services(process.env.TWILIO_VERIFY_SID)
        .verificationChecks.create({ 
          to: session.phone_number, 
          code: otpCode 
        });

      if (verificationCheck.status !== 'approved') {
        return sendResponse(res, 400, 'Invalid OTP code. Please try again.');
      }

      // Get user data
      const { data: user, error: userError } = await supabase
        .from('users')
        .select('id, email, full_name, phone_number, role, date_of_birth, created_at, updated_at, two_factor_enabled, profile_image')
        .eq('id', session.user_id)
        .is('deleted_at', null)
        .single();

      if (userError || !user) {
        logger.error('User not found during OTP verification:', userError);
        return sendResponse(res, 401, 'User not found');
      }

      // Mark session as verified and clean up
      await supabase
        .from('phone_login_sessions')
        .delete()
        .eq('session_token', sessionToken);

      // Update user's last login
      await supabase
        .from('users')
        .update({ updated_at: new Date().toISOString() })
        .eq('id', user.id);

      // Generate JWT token
      const token = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
      );

      logger.info(`Phone login successful for user ${user.id}`);

      return sendResponse(res, 200, 'Phone login successful', {
        user,
        token
      });

    } catch (twilioError) {
      logger.error('Twilio verification error:', twilioError);
      
      if (twilioError.code === 60202) {
        return sendResponse(res, 429, 'Max verification attempts reached. Please request a new OTP.');
      }
      
      return sendResponse(res, 400, 'OTP verification failed. Please try again.');
    }

  } catch (error) {
    logger.error('OTP verification error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Resend Phone OTP
router.post('/resend-phone-otp', otpLimiter, async (req, res) => {
  try {
    const { sessionToken } = req.body;

    if (!sessionToken) {
      return sendResponse(res, 400, 'Session token is required');
    }

    const supabase = getSupabaseClient();

    // Get session data
    const { data: session, error: sessionError } = await supabase
      .from('phone_login_sessions')
      .select('user_id, phone_number, expires_at, verified')
      .eq('session_token', sessionToken)
      .maybeSingle();

    if (sessionError) {
      logger.error('Database error during OTP resend:', sessionError);
      return sendResponse(res, 500, 'Database error');
    }

    if (!session) {
      return sendResponse(res, 400, 'Invalid session');
    }

    if (session.verified) {
      return sendResponse(res, 400, 'Session already verified');
    }

    try {
      // Send new OTP
      const verification = await client.verify.v2
        .services(process.env.TWILIO_VERIFY_SID)
        .verifications.create({ 
          to: session.phone_number, 
          channel: 'sms',
          customFriendlyName: 'Healthcare App Login'
        });

      // Update session expiry
      const newExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
      await supabase
        .from('phone_login_sessions')
        .update({ expires_at: newExpiresAt.toISOString() })
        .eq('session_token', sessionToken);

      logger.info(`OTP resent to ${session.phone_number}`);

      return sendResponse(res, 200, 'OTP resent successfully', {
        expiresIn: OTP_EXPIRY_MINUTES * 60
      });

    } catch (twilioError) {
      logger.error('Twilio resend error:', twilioError);
      
      if (twilioError.code === 60203) {
        return sendResponse(res, 429, 'Too many attempts. Please wait before requesting another OTP.');
      }
      
      return sendResponse(res, 500, 'Failed to resend OTP. Please try again.');
    }

  } catch (error) {
    logger.error('OTP resend error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// POST - Create user profile
router.post('/user-profile',authenticateToken,validateProfileCreation,handleValidationErrors, async (req, res) => {
    try {
      const { age, bmi, medical_conditions, previous_pregnancies, gestational_week, weight } = req.body;
      const user_id = req.user?.id;

   
      const supabase = getSupabaseClient();

      // Check if profile already exists for this user
      const { data: existingProfile, error: checkError } = await supabase
        .from('users_profile')
        .select('id')
        .eq('user_id', user_id)
        .maybeSingle();

      if (checkError) {
        logger.error('Database check error:', checkError);
        return sendResponse(res, 500, 'Database error');
      }

      if (existingProfile) {
        return sendResponse(res, 409, 'Profile already exists for this user');
      }

      // Create profile
      const { data: profile, error } = await supabase
        .from('users_profile')
        .insert([{
          user_id,
          age,
          bmi,
          medical_conditions,
          previous_pregnancies,
          gestational_week,
          weight
        }])
        .select()
        .single();

      if (error) {
        logger.error('Profile creation error:', error);
        return sendResponse(res, 500, 'Failed to create profile');
      }

      logger.info(`User profile created for user: ${user_id}`);

      return sendResponse(res, 201, 'Profile created successfully', { profile });

    } catch (error) {
      logger.error('Profile creation error:', error);
      return sendResponse(res, 500, 'Internal server error');
    }
  }
);


// GET - Get all user profiles (admin only or with pagination)
router.get('/user-profiles', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const supabase = getSupabaseClient();

    // Validate pagination parameters
    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    
    if (pageNum < 1 || limitNum < 1 || limitNum > 100) {
      return sendResponse(res, 400, 'Invalid pagination parameters');
    }

    // Calculate offset for pagination
    const offset = (pageNum - 1) * limitNum;

    const { data: profiles, error, count } = await supabase
      .from('users_profile')
      .select('*, users(email, full_name)', { count: 'exact' })
      .range(offset, offset + limitNum - 1)
      .order('created_at', { ascending: false });

    if (error) {
      logger.error('Profiles fetch error:', error);
      return sendResponse(res, 500, 'Failed to fetch profiles');
    }

    return sendResponse(res, 200, 'Profiles retrieved successfully', {
      profiles,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: count,
        totalPages: Math.ceil(count / limitNum)
      }
    });

  } catch (error) {
    logger.error('Profiles fetch error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// GET - Get current user's profile
router.get('/user-profile/me', authenticateToken, async (req, res) => {
  try {
    const user_id = req.user.id;
    const supabase = getSupabaseClient();

    const { data: profile, error } = await supabase
      .from('users_profile')
      .select('*')
      .eq('user_id', user_id)
      .maybeSingle();

    if (error) {
      logger.error('Profile fetch error:', error);
      return sendResponse(res, 500, 'Failed to fetch profile');
    }

    if (!profile) {
      return sendResponse(res, 404, 'Profile not found');
    }

    return sendResponse(res, 200, 'Profile retrieved successfully', { profile });

  } catch (error) {
    logger.error('Profile fetch error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// GET - Get specific user profile by ID
router.get('/user-profile/:id', authenticateToken, param('id').isInt(), handleValidationErrors, async (req, res) => {
  try {
    const profileId = req.params.id;
    const supabase = getSupabaseClient();

    const { data: profile, error } = await supabase
      .from('users_profile')
      .select('*, users(email, full_name)')
      .eq('id', profileId)
      .maybeSingle();

    if (error) {
      logger.error('Profile fetch error:', error);
      return sendResponse(res, 500, 'Failed to fetch profile');
    }

    if (!profile) {
      return sendResponse(res, 404, 'Profile not found');
    }

    // Authorization check - users can only view their own profile unless they're admin
    if (profile.user_id !== req.user.id && req.user.role !== 'admin') {
      return sendResponse(res, 403, 'Access denied');
    }

    return sendResponse(res, 200, 'Profile retrieved successfully', { profile });

  } catch (error) {
    logger.error('Profile fetch error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// PUT - Update user profile
router.put('/user-profile/:id', authenticateToken, validateProfileUpdate, handleValidationErrors, async (req, res) => {
  try {
    const profileId = req.params.id;
    const { age, bmi, medical_conditions, previous_pregnancies, gestational_week, weight } = req.body;
    const supabase = getSupabaseClient();

    // Check if profile exists and belongs to user (or user is admin)
    const { data: existingProfile, error: checkError } = await supabase
      .from('users_profile')
      .select('user_id')
      .eq('id', profileId)
      .maybeSingle();

    if (checkError) {
      logger.error('Database check error:', checkError);
      return sendResponse(res, 500, 'Database error');
    }

    if (!existingProfile) {
      return sendResponse(res, 404, 'Profile not found');
    }

    // Authorization check
    if (existingProfile.user_id !== req.user.id && req.user.role !== 'admin') {
      return sendResponse(res, 403, 'Access denied');
    }

    // Prepare update object (only include provided fields)
    const updateData = {};
    if (age !== undefined) updateData.age = age;
    if (bmi !== undefined) updateData.bmi = bmi;
    if (medical_conditions !== undefined) updateData.medical_conditions = medical_conditions;
    if (previous_pregnancies !== undefined) updateData.previous_pregnancies = previous_pregnancies;
    if (gestational_week !== undefined) updateData.gestational_week = gestational_week;
    if (weight !== undefined) updateData.weight = weight;
    updateData.updated_at = new Date().toISOString();

    if (Object.keys(updateData).length === 1) { // only updated_at
      return sendResponse(res, 400, 'No valid fields provided for update');
    }

    // Update profile
    const { data: profile, error } = await supabase
      .from('users_profile')
      .update(updateData)
      .eq('id', profileId)
      .select()
      .single();

    if (error) {
      logger.error('Profile update error:', error);
      return sendResponse(res, 500, 'Failed to update profile');
    }

    logger.info(`User profile updated: ${profileId}`);

    return sendResponse(res, 200, 'Profile updated successfully', { profile });

  } catch (error) {
    logger.error('Profile update error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// DELETE - Delete user profile
router.delete('/user-profile/:id', authenticateToken, param('id').isInt(), handleValidationErrors, async (req, res) => {
  try {
    const profileId = req.params.id;
    const supabase = getSupabaseClient();

    // Check if profile exists and belongs to user (or user is admin)
    const { data: existingProfile, error: checkError } = await supabase
      .from('users_profile')
      .select('user_id')
      .eq('id', profileId)
      .maybeSingle();

    if (checkError) {
      logger.error('Database check error:', checkError);
      return sendResponse(res, 500, 'Database error');
    }

    if (!existingProfile) {
      return sendResponse(res, 404, 'Profile not found');
    }

    // Authorization check
    if (existingProfile.user_id !== req.user.id && req.user.role !== 'admin') {
      return sendResponse(res, 403, 'Access denied');
    }

    // Delete profile
    const { error } = await supabase
      .from('users_profile')
      .delete()
      .eq('id', profileId);

    if (error) {
      logger.error('Profile deletion error:', error);
      return sendResponse(res, 500, 'Failed to delete profile');
    }

    logger.info(`User profile deleted: ${profileId}`);

    return sendResponse(res, 200, 'Profile deleted successfully');

  } catch (error) {
    logger.error('Profile deletion error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Health check endpoint
router.get('/health', async (req, res) => {
  try {
    const supabase = getSupabaseClient();
    
    // Simple database connectivity test
    const { error } = await supabase
      .from('users')
      .select('id')
      .limit(1);
    
    if (error) {
      logger.error('Health check database error:', error);
      return sendResponse(res, 503, 'Database connection failed');
    }

    return sendResponse(res, 200, 'Service is healthy', {
      timestamp: new Date().toISOString(),
      database: 'connected',
      services: {
        twilio: !!process.env.TWILIO_SID,
        cloudinary: !!process.env.CLOUDINARY_CLOUD_NAME,
        email: !!(process.env.EMAIL_USER && process.env.EMAIL_PASS)
      }
    });
  } catch (error) {
    logger.error('Health check error:', error);
    return sendResponse(res, 500, 'Service unhealthy');
  }
});

// Logout endpoint (for token blacklisting if implemented)
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    // In a production environment, you might want to:
    // 1. Add token to blacklist
    // 2. Clear any server-side sessions
    // 3. Log the logout event
    
    logger.info(`User logged out: ${req.user.id}`);
    
    return sendResponse(res, 200, 'Logged out successfully');
  } catch (error) {
    logger.error('Logout error:', error);
    return sendResponse(res, 500, 'Internal server error');
  }
});

// Error handling middleware
router.use((error, req, res, next) => {
  logger.error('Unhandled route error:', error);
  return sendResponse(res, 500, 'Internal server error');
});

module.exports = router;