const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { validateKickCount } = require('../middleware/validation');
const { requireRole } = require('../middleware/auth');
const logger = require('../utils/logger');

const router = express.Router();

// Record kick count
router.post('/', requireRole(['mother']), validateKickCount, async (req, res) => {
  try {
    const { count, notes } = req.body;
    const supabase = getSupabaseClient();

    // Get current active pregnancy
    const { data: pregnancy } = await supabase
      .from('pregnancies')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .single();

    if (!pregnancy) {
      return res.status(404).json({ error: 'No active pregnancy found' });
    }

    const kickCountId = uuidv4();
    const { data: kickCount, error } = await supabase
      .from('kick_counts')
      .insert([{
        id: kickCountId,
        pregnancy_id: pregnancy.id,
        timestamp: new Date().toISOString(),
        count,
        notes
      }])
      .select()
      .single();

    if (error) {
      logger.error('Kick count creation error:', error);
      return res.status(500).json({ error: 'Failed to record kick count' });
    }

    res.status(201).json({
      message: 'Kick count recorded successfully',
      kickCount
    });

  } catch (error) {
    logger.error('Record kick count error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get kick counts for current pregnancy
router.get('/', async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const supabase = getSupabaseClient();

    // Get current active pregnancy
    const { data: pregnancy } = await supabase
      .from('pregnancies')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('status', 'active')
      .single();

    if (!pregnancy) {
      return res.status(404).json({ error: 'No active pregnancy found' });
    }

    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - parseInt(days));

    const { data: kickCounts, error } = await supabase
      .from('kick_counts')
      .select('*')
      .eq('pregnancy_id', pregnancy.id)
      .gte('timestamp', fromDate.toISOString())
      .order('timestamp', { ascending: false });

    if (error) {
      logger.error('Get kick counts error:', error);
      return res.status(500).json({ error: 'Failed to fetch kick counts' });
    }

    // Calculate daily averages
    const dailyAverages = {};
    kickCounts.forEach(kick => {
      const date = kick.timestamp.split('T')[0];
      if (!dailyAverages[date]) {
        dailyAverages[date] = { total: 0, sessions: 0 };
      }
      dailyAverages[date].total += kick.count;
      dailyAverages[date].sessions += 1;
    });

    Object.keys(dailyAverages).forEach(date => {
      dailyAverages[date].average = Math.round(dailyAverages[date].total / dailyAverages[date].sessions);
    });

    res.json({
      kickCounts,
      dailyAverages,
      summary: {
        totalSessions: kickCounts.length,
        totalKicks: kickCounts.reduce((sum, kick) => sum + kick.count, 0),
        averagePerSession: kickCounts.length > 0 
          ? Math.round(kickCounts.reduce((sum, kick) => sum + kick.count, 0) / kickCounts.length)
          : 0
      }
    });

  } catch (error) {
    logger.error('Get kick counts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// routes/kickCount.js (Add to existing file)
router.get("/chart", async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const supabase = getSupabaseClient();

    // Find active pregnancy for user
    const { data: pregnancy, error: pregError } = await supabase
      .from("pregnancies")
      .select("id")
      .eq("user_id", req.user.id)
      .eq("status", "active")
      .single();

    if (pregError || !pregnancy) {
      return res.status(404).json({ error: "No active pregnancy found" });
    }

    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - parseInt(days));

    const { data: kickCounts, error } = await supabase
      .from("kick_counts")
      .select("timestamp, count")
      .eq("pregnancy_id", pregnancy.id)
      .gte("timestamp", fromDate.toISOString())
      .order("timestamp", { ascending: true });

    if (error) {
      return res.status(500).json({ error: "Failed to fetch chart data" });
    }

    // Aggregate by date
    const dateMap = {};
    kickCounts.forEach(kick => {
      const date = kick.timestamp.split("T")[0];
      if (!dateMap[date]) dateMap[date] = { total: 0, sessions: 0 };
      dateMap[date].total += kick.count;
      dateMap[date].sessions += 1;
    });

    const labels = [];
    const counts = [];
    Object.keys(dateMap)
      .sort()
      .forEach(date => {
        labels.push(date);
        counts.push(Math.round(dateMap[date].total / dateMap[date].sessions));
      });

    res.json({ labels, counts });
  } catch (err) {
    console.error("Chart error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});


module.exports = router;
