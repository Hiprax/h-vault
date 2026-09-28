import { Router } from 'express';
import { markReleaseNotesSeenSchema } from '@hvault/shared';
import { authenticate } from '../middleware/auth.js';
import { validate } from '../middleware/validate.js';
import { generalAuthLimiter } from '../middleware/rateLimiter.js';
import {
  checkForUpdate,
  getReleaseStatus,
  listReleaseNotes,
  markReleaseNotesSeen,
} from '../controllers/releasesController.js';

const router = Router();

// Signed-in only: the running version is deliberately never part of an
// unauthenticated response (see `healthController`), and these routes carry it.
router.use(authenticate);

// `generalAuthLimiter` (60/user/min) on all four. Each is one request per
// deliberate action or per sign-in, never a per-row fan-out, and "Check now"
// needs no budget of its own: whoever calls it, the server asks GitHub at most
// once per `UPDATE_CHECK_MIN_INTERVAL_MS` and answers from the stored state
// otherwise.
router.get('/status', generalAuthLimiter, getReleaseStatus);
router.get('/notes', generalAuthLimiter, listReleaseNotes);
router.post(
  '/seen',
  generalAuthLimiter,
  validate(markReleaseNotesSeenSchema, 'body'),
  markReleaseNotesSeen,
);
router.post('/update-check', generalAuthLimiter, checkForUpdate);

export default router;
