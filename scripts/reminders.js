const cron = require('node-cron');
const { getSupabaseClient } = require('../config/database');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const logger = require('../utils/logger');

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const scheduleReminders = () => {
  // Run every day at 8 AM
  cron.schedule('0 8 * * *', async () => {
    try {
      const supabase = getSupabaseClient();
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      const tomorrowStart = tomorrow.toISOString().split('T')[0] + 'T00:00:00Z';
      const tomorrowEnd = tomorrow.toISOString().split('T')[0] + 'T23:59:59Z';

      const { data: appointments, error } = await supabase
        .from('appointments')
        .select(`
          *,
          user:users!appointments_user_id_fkey(email, phone_number, full_name),
          doctor:users!appointments_doctor_id_fkey(full_name)
        `)
        .eq('status', 'scheduled')
        .gte('scheduled_at', tomorrowStart)
        .lte('scheduled_at', tomorrowEnd);

      if (error) {
        logger.error('Fetch appointments for reminders error:', error);
        return;
      }

      for (const appt of appointments) {
        // Send email reminder
        await transporter.sendMail({
          to: appt.user.email,
          subject: 'Appointment Reminder',
          text: `Dear ${appt.user.full_name},\n\nYou have an appointment with Dr. ${appt.doctor.full_name} scheduled for ${new Date(appt.scheduled_at).toLocaleString()}. Please arrive 15 minutes early.\n\nNotes: ${appt.notes || 'None'}`,
        });

        // Send SMS reminder
        if (appt.user.phone_number) {
          await client.messages.create({
            body: `Reminder: Your appointment with Dr. ${appt.doctor.full_name} is on ${new Date(appt.scheduled_at).toLocaleString()}.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: appt.user.phone_number,
          });
        }

        logger.info(`Reminder sent for appointment ${appt.id}`);
      }
    } catch (error) {
      logger.error('Appointment reminder cron error:', error);
    }
  });

  logger.info('Appointment reminder cron job scheduled');
};

module.exports = { scheduleReminders };