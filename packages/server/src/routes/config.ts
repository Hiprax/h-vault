import { Router } from 'express';
import { getPublicConfig } from '../controllers/configController.js';
import { healthLimiter } from '../middleware/rateLimiter.js';

const router = Router();

// Public, unauthenticated endpoint. Rate-limited like /health so the open
// endpoint cannot be flooded. Returns only the non-sensitive client-side
// File Encryption size guardrail.
router.get('/config', healthLimiter, getPublicConfig);

export default router;
