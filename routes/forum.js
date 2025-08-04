const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { getSupabaseClient } = require('../config/database');
const { body, validationResult } = require('express-validator');
const logger = require('../utils/logger');
const { requireRole } = require('../middleware/auth');


const router = express.Router();

// Validation middleware
const validatePost = [
  body('title').trim().isLength({ min: 5, max: 255 }),
  body('body').trim().isLength({ min: 10, max: 5000 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }
    next();
  }
];

const validateComment = [
  body('body').trim().isLength({ min: 1, max: 1000 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }
    next();
  }
];

// Create forum post
router.post('/posts', validatePost, async (req, res) => {
  try {
    const { title, body } = req.body;
    const supabase = getSupabaseClient();

    const postId = uuidv4();
    const { data: post, error } = await supabase
      .from('forum_posts')
      .insert([{
        id: postId,
        user_id: req.user.id,
        title,
        body,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }])
      .select(`
        *,
        user:users!forum_posts_user_id_fkey(id, full_name)
      `)
      .single();

    if (error) {
      logger.error('Forum post creation error:', error);
      return res.status(500).json({ error: 'Failed to create post' });
    }

    res.status(201).json({
      message: 'Forum post created successfully',
      post
    });

  } catch (error) {
    logger.error('Create forum post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get forum posts
router.get('/posts', async (req, res) => {
  try {
    const { limit = 10, offset = 0, search } = req.query;
    const supabase = getSupabaseClient();

    let query = supabase
      .from('forum_posts')
      .select(`
        *,
        user:users!forum_posts_user_id_fkey(id, full_name),
        comments:forum_comments(count)
      `)
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (search) {
      query = query.or(`title.ilike.%${search}%,body.ilike.%${search}%`);
    }

    const { data: posts, error } = await query;

    if (error) {
      logger.error('Get forum posts error:', error);
      return res.status(500).json({ error: 'Failed to fetch posts' });
    }

    res.json({ posts });

  } catch (error) {
    logger.error('Get forum posts error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single forum post with comments
router.get('/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const supabase = getSupabaseClient();

    const { data: post, error: postError } = await supabase
      .from('forum_posts')
      .select(`
        *,
        user:users!forum_posts_user_id_fkey(id, full_name)
      `)
      .eq('id', id)
      .single();

    if (postError) {
      logger.error('Get forum post error:', postError);
      return res.status(500).json({ error: 'Failed to fetch post' });
    }

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const { data: comments, error: commentsError } = await supabase
      .from('forum_comments')
      .select(`
        *,
        user:users!forum_comments_user_id_fkey(id, full_name)
      `)
      .eq('post_id', id)
      .order('created_at', { ascending: true });

    if (commentsError) {
      logger.error('Get forum comments error:', commentsError);
      return res.status(500).json({ error: 'Failed to fetch comments' });
    }

    res.json({
      post: {
        ...post,
        comments: comments || []
      }
    });

  } catch (error) {
    logger.error('Get forum post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add comment to forum post
router.post('/posts/:id/comments', validateComment, async (req, res) => {
  try {
    const { id } = req.params;
    const { body } = req.body;
    const supabase = getSupabaseClient();

    // Verify post exists
    const { data: post } = await supabase
      .from('forum_posts')
      .select('id')
      .eq('id', id)
      .single();

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const commentId = uuidv4();
    const { data: comment, error } = await supabase
      .from('forum_comments')
      .insert([{
        id: commentId,
        post_id: id,
        user_id: req.user.id,
        body,
        created_at: new Date().toISOString()
      }])
      .select(`
        *,
        user:users!forum_comments_user_id_fkey(id, full_name)
      `)
      .single();

    if (error) {
      logger.error('Forum comment creation error:', error);
      return res.status(500).json({ error: 'Failed to create comment' });
    }

    res.status(201).json({
      message: 'Comment added successfully',
      comment
    });

  } catch (error) {
    logger.error('Add forum comment error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// routes/forum.js (Add to existing file)
router.patch('/posts/:id/moderate', requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // 'approved', 'rejected', 'pending'
    const supabase = getSupabaseClient();

    if (!['approved', 'rejected', 'pending'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const { data: post, error } = await supabase
      .from('forum_posts')
      .update({ status, updated_at: new Date().toISOString() })
      .eq('id', id)
      .select(`
        *,
        user:users!forum_posts_user_id_fkey(id, full_name)
      `)
      .single();

    if (error) {
      logger.error('Moderate post error:', error);
      return res.status(500).json({ error: 'Failed to moderate post' });
    }

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json({ message: 'Post moderated successfully', post });
  } catch (error) {
    logger.error('Moderate post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/posts/:id', requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const supabase = getSupabaseClient();

    const { data: post, error } = await supabase
      .from('forum_posts')
      .delete()
      .eq('id', id)
      .select()
      .single();

    if (error) {
      logger.error('Delete post error:', error);
      return res.status(500).json({ error: 'Failed to delete post' });
    }

    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    logger.error('Delete post error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
module.exports = router;
