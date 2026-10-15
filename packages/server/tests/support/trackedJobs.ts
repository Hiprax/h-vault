import { getRunningJobs } from '../../src/utils/jobTracker.js';

/**
 * Waits until every tracked background job has settled, including one a response's
 * `close` listener registers just after the response, such as a security notice
 * (F-26) sent in the background after a request. A test that counts mails, or
 * clears its mock relay, after a request must call this first, or a notice landing
 * later is a race rather than an assertion.
 */
export async function settleTrackedJobs(): Promise<void> {
  for (let round = 0; round < 50; round += 1) {
    // Lets a response's `close` listener register its job first.
    await new Promise((resolve) => setImmediate(resolve));
    const jobs = getRunningJobs();
    if (jobs.length === 0) return;
    await Promise.allSettled(jobs);
  }
}
