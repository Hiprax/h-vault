#!/usr/bin/env tsx
/**
 * Production Index Creation Script
 *
 * In production, Mongoose autoIndex is disabled for performance.
 * Run this script after deployment to create all required database indexes.
 *
 * Usage:
 *   npx tsx packages/server/scripts/create-indexes.ts
 *
 * Requires MONGODB_URI environment variable (or .env file).
 */

import mongoose from 'mongoose';
import { config } from '../src/config/index.js';
// The model list lives in indexedModels.ts so it can be asserted by a drift
// test — guaranteeing every model with declared indexes is created here.
import { indexedModels } from './indexedModels.js';
import { createIndexesWithCurrentRetention } from '../src/utils/ttlIndexReconcile.js';

async function createIndexes(): Promise<void> {
  console.log(`Connecting to MongoDB: ${config.MONGODB_URI.replace(/\/\/[^@]+@/, '//***@')}`);

  await mongoose.connect(config.MONGODB_URI, {
    maxPoolSize: config.MONGO_MAX_POOL_SIZE,
    minPoolSize: config.MONGO_MIN_POOL_SIZE,
    serverSelectionTimeoutMS: 10000,
  });

  console.log('Connected. Creating indexes...\n');

  for (const { name, model } of indexedModels) {
    try {
      // A TTL index whose retention setting changed since it was built is rebuilt
      // rather than refused (see ttlIndexReconcile.ts).
      const rebuilt = await createIndexesWithCurrentRetention(model);
      for (const index of rebuilt) {
        console.log(
          `  [REBUILT] ${name}.${index.name}: retention ${String(index.fromSeconds)}s -> ${String(index.toSeconds)}s`,
        );
      }
      console.log(`  [OK] ${name}`);
    } catch (error) {
      console.error(`  [FAIL] ${name}:`, error instanceof Error ? error.message : error);
      process.exitCode = 1;
    }
  }

  console.log('\nIndex creation complete.');
  await mongoose.disconnect();
}

createIndexes().catch((error: unknown) => {
  console.error('Fatal error:', error);
  process.exitCode = 1;
});
