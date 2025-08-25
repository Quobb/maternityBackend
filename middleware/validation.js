const { body, validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

const validateRegistration = [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  body('full_name').trim().isLength({ min: 2, max: 255 }),
  body('role').isIn(['mother', 'doctor']),
  handleValidationErrors
];

const validateLogin = [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  handleValidationErrors
];

const validatePregnancy = [
  body('start_date').isISO8601().toDate(),
  body('due_date').isISO8601().toDate(),
  body('lmp_date').optional().isISO8601().toDate().custom((lmp_date, { req }) => {
    if (lmp_date) {
      const lmp = new Date(lmp_date);
      const dueDate = new Date(req.body.due_date);
      const expectedDueDate = new Date(lmp);
      expectedDueDate.setFullYear(lmp.getFullYear() + 1);
      expectedDueDate.setMonth(lmp.getMonth() - 3);
      expectedDueDate.setDate(lmp.getDate() + 7);
      if (Math.abs(dueDate - expectedDueDate) > 24 * 60 * 60 * 1000) {
        throw new Error('Due date does not align with Naegele’s rule');
      }
    }
    return true;
  }),
  handleValidationErrors
];

const validateKickCount = [
  body('count').isInt({ min: 0 }),
  body('notes').optional().trim().isLength({ max: 500 }),
  handleValidationErrors
];

const validateAppointment = [
  body('doctor_id').isUUID(),
 body('appointment_date')
    .isISO8601()
    .withMessage('Appointment date must be a valid date (YYYY-MM-DD)'),

  body('time')
    .matches(/^\d{2}:\d{2}(:\d{2})?$/)
    .withMessage('Time must be in HH:MM or HH:MM:SS format'),

  body('notes')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Notes cannot exceed 1000 characters'),
  handleValidationErrors
];


module.exports = {
  validateRegistration,
  validateLogin,
  validatePregnancy,
  validateKickCount,
  validateAppointment,
  handleValidationErrors
};

