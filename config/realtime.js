const { getSupabaseClient } = require('./database');
const logger = require('../utils/logger');
const { getCached, setCached } = require('./cache');
const nodemailer = require('nodemailer');
const twilio = require('twilio');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');

const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const initializeRealtime = () => {
  const supabase = getSupabaseClient();

  supabase
    .channel('wearable_data_changes')
    .on(
      'postgres_changes',
      {
        event: 'INSERT',
        schema: 'public',
        table: 'wearable_data',
      },
      async (payload) => {
        try {
          const userId = payload.new.user_id;
          const cacheKey = `realtime:${userId}:wearable`;
          const lastNotified = await getCached(cacheKey);

          if (lastNotified && Date.now() - parseInt(lastNotified) < 60 * 1000) {
            return;
          }

          const { data: user } = await supabase
            .from('users')
            .select('email, phone_number, full_name, age')
            .eq('id', userId)
            .single();

          const { data: pregnancy } = await supabase
            .from('pregnancies')
            .select('start_date')
            .eq('user_id', userId)
            .eq('status', 'active')
            .single();

          const input = {
            Age: user?.age || 25,
            SystolicBP: payload.new.blood_pressure ? parseInt(payload.new.blood_pressure.split('/')[0]) : 120,
            DiastolicBP: payload.new.blood_pressure ? parseInt(payload.new.blood_pressure.split('/')[1]) : 80,
            BS: user?.medical_conditions?.includes('diabetes') ? 6.0 : 4.5,
            BodyTemp: payload.new.temperature ? (payload.new.temperature * 9/5 + 32) : 98.6,
            HeartRate: payload.new.heart_rate || 80,
          };

          let riskLevel;
          try {
            const response = await axios.post(
              process.env.MODEL_API_URL + '/risk-assessment',
              input,
              { headers: { 'Content-Type': 'application/json' } }
            );
            riskLevel = response.data.risk_level;
          } catch (error) {
            logger.error('Model API error:', error);
            riskLevel = 'low';
            if (input.HeartRate > 120 || input.HeartRate < 60 || input.SystolicBP > 140 || input.DiastolicBP > 90 || input.BodyTemp > 100.4) {
              riskLevel = 'high';
            } else if (input.HeartRate > 100 || input.SystolicBP > 120 || input.BS > 5.5) {
              riskLevel = 'medium';
            }
          }

          if (riskLevel === 'high') {
            const alertId = uuidv4();
            await supabase
              .from('emergency_alerts')
              .insert([
                {
                  id: alertId,
                  user_id: userId,
                  type: 'high_risk',
                  message: `High risk detected: ${JSON.stringify(input)}`,
                  triggered_at: new Date().toISOString(),
                  resolved: false,
                },
              ]);
          }

          const message = `New wearable data: HR: ${payload.new.heart_rate || 'N/A'}, BP: ${payload.new.blood_pressure || 'N/A'}, Temp: ${payload.new.temperature || 'N/A'}, Steps: ${payload.new.steps || 'N/A'}, Risk: ${riskLevel}`;

          if (user.email) {
            await transporter.sendMail({
              to: user.email,
              subject: 'Wearable Data Update',
              text: `Dear ${user.full_name},\n\n${message}`,
            });
          }

          if (user.phone_number) {
            await client.messages.create({
              body: message,
              from: process.env.TWILIO_PHONE_NUMBER,
              to: user.phone_number,
            });
          }

          await setCached(cacheKey, Date.now().toString(), 60);
          logger.info(`Real-time notification sent to user ${userId}: ${message}`);
        } catch (error) {
          logger.error('Real-time wearable notification error:', error);
        }
      }
    )
    .subscribe();

  supabase
    .channel('emergency_alerts_changes')
    .on(
      'postgres_changes',
      {
        event: 'INSERT',
        schema: 'public',
        table: 'emergency_alerts',
        filter: 'resolved=eq.false',
      },
      async (payload) => {
        try {
          const userId = payload.new.user_id;
          const cacheKey = `realtime:${userId}:emergency`;
          const lastNotified = await getCached(cacheKey);

          if (lastNotified && Date.now() - parseInt(lastNotified) < 60 * 1000) {
            return;
          }

          const { data: user } = await supabase
            .from('users')
            .select('email, phone_number, full_name')
            .eq('id', userId)
            .single();

          const message = `Emergency Alert: ${payload.new.type} at ${new Date(payload.new.triggered_at).toLocaleString()}${payload.new.message ? ` - ${payload.new.message}` : ''}`;

          const { data: contacts } = await supabase
            .from('emergency_contacts')
            .select('email, phone_number, name')
            .eq('user_id', userId);

          for (const contact of contacts) {
            if (contact.email) {
              await transporter.sendMail({
                to: contact.email,
                subject: `Emergency Alert for ${user.full_name}`,
                text: message,
              });
            }
            if (contact.phone_number) {
              await client.messages.create({
                body: message,
                from: process.env.TWILIO_PHONE_NUMBER,
                to: contact.phone_number,
              });
            }
          }

          if (user.email) {
            await transporter.sendMail({
              to: user.email,
              subject: 'Emergency Alert',
              text: message,
            });
          }
          if (user.phone_number) {
            await client.messages.create({
              body: message,
              from: process.env.TWILIO_PHONE_NUMBER,
              to: user.phone_number,
            });
          }

          await setCached(cacheKey, Date.now().toString(), 60);
          logger.info(`Real-time emergency alert notification sent to user ${userId}`);
        } catch (error) {
          logger.error('Real-time emergency notification error:', error);
        }
      }
    )
    .subscribe();

  logger.info('✅ Real-time subscriptions initialized');
};

module.exports = { initializeRealtime };