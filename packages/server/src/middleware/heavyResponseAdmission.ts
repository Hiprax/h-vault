import { MAX_IN_FLIGHT_HEAVY_RESPONSES_PER_USER } from '@hvault/shared';
import { createModuleLogger } from '../utils/logger.js';
import { heavyResponseSemaphore, heavyResponseUserQuota } from '../utils/heavyResponseBudget.js';
import { createSlotHolder } from './admission.js';

const logger = createModuleLogger('heavy-response-admission');

/**
 * Admission to the three routes that build a whole vault's worth of JSON:
 * `GET /backup/download`, `POST /backup/trigger` and `POST /tools/export`. Mounted
 * after each route's rate limiter, as {@link holdHeavyResponseSlot} in front of the
 * handler and {@link holdingHeavyResponseSlot} around it.
 *
 * The mechanics are the two copies every slot holder shares
 * (`middleware/admission.ts`): the share is charged before the slot is asked for, a
 * request past the process budget WAITS (these carry no body, or one the 2 MB
 * global parser has already read, so a queued request costs a socket), and the slot
 * comes back only once the response has closed AND the handler has settled. For a
 * response that is what the budget is for: Express does not cancel a handler whose
 * client left, and a download that is still reading the vault holds its memory
 * whether or not anyone is listening.
 */

/**
 * The refusal past the share: 409, remedy first, under 200 characters, NO `data`
 * (a 409 carrying `data.vaultKeyVersion` means "your vault key is stale" to every
 * client consumer, and this is not that).
 */
const HEAVY_RESPONSE_BUSY_MESSAGE =
  'Wait for the backup or export already in progress on this account to finish, then try again.';

const heavyResponseSlot = createSlotHolder({
  semaphore: heavyResponseSemaphore,
  quota: heavyResponseUserQuota,
  busyMessage: HEAVY_RESPONSE_BUSY_MESSAGE,
  logRefusal() {
    logger.warn('Heavy response refused: the account already has one in progress', {
      limit: MAX_IN_FLIGHT_HEAVY_RESPONSES_PER_USER,
    });
  },
  handlerName: 'heavyResponseHandler',
  unadmittedMessage: 'Heavy-response handler reached without an admission slot',
});

/**
 * Charges this account's share, then holds one heavy-response slot until the
 * response has closed AND the handler has settled.
 */
export const holdHeavyResponseSlot = heavyResponseSlot.hold;

/**
 * Wraps a heavy route's handler so its slot is held until the handler has SETTLED,
 * not merely until the response closed. Reached without a slot, it refuses with 500
 * rather than run unbudgeted.
 */
export const holdingHeavyResponseSlot = heavyResponseSlot.holding;
