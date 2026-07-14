import { Router } from 'express';
import { healthCheck } from '../controllers/healthController.js';
import { healthLimiter } from '../middleware/rateLimiter.js';

const router = Router();

router.get('/health', healthLimiter, healthCheck);

export default router;
