import mongoose from 'mongoose';
import { createLogger } from '@hiprax/logger';
import { config } from './index.js';

// Import models so schema index definitions are registered before the check
import '../models/User.js';
import '../models/VaultItem.js';
import '../models/Folder.js';
import '../models/RefreshToken.js';
import '../models/AuditLog.js';
import '../models/BackupLog.js';
import '../models/JobLock.js';

const logger = createLogger({ moduleName: 'database' });

const MAX_RETRY_ATTEMPTS = 5;
const RETRY_DELAY_MS = 5000;

/**
 * Verifies that the connected MongoDB server's topology matches what the URI
 * advertises. If `MONGODB_URI` requests `?replicaSet=<name>` but the server's
 * `hello` response carries no `setName` (or a different one), the runtime
 * `supportsTransactions()` check still returns true (it inspects the URI
 * option) but `session.withTransaction()` will throw at runtime.
 *
 * Be precise about what happens then, because the obvious guess is wrong: NO
 * caller catches that throw. `vaultController.bulkReEncrypt`,
 * `folderController` and `toolsController.executeImportOperations` all take the
 * transactional branch and let the error surface as a 500. There is no silent
 * fallback — the non-transactional branch is reached only when
 * `supportsTransactions()` is false. The request therefore fails closed,
 * writing nothing, which is safe but total: the affected endpoints simply stop
 * working. Surface this loudly at boot rather than letting it manifest later.
 */
export async function verifyTopology(): Promise<void> {
  try {
    const client = mongoose.connection.getClient();
    const requestedReplicaSet = client.options.replicaSet;
    if (!requestedReplicaSet) {
      return;
    }

    const db = mongoose.connection.db;
    if (!db) {
      return;
    }

    const helloResult = (await db.admin().command({ hello: 1 })) as {
      setName?: string;
    };
    const actualSetName = helloResult.setName;

    if (!actualSetName) {
      logger.warn(
        `MONGODB_URI requests replica set '${requestedReplicaSet}' but server reports topology without a setName. Every transactional endpoint (vault-key rotation, folder reorder, import) will fail with a 500 rather than falling back, because the URI still advertises a replica set; ensure rs.initiate() succeeded on the deployment.`,
      );
    } else if (actualSetName !== requestedReplicaSet) {
      logger.warn(
        `MONGODB_URI requests replica set '${requestedReplicaSet}' but server reports setName '${actualSetName}' — topology mismatch. Verify the deployment's replica-set name matches the URI.`,
      );
    }
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.warn(`Topology verification failed: ${message}`);
  }
}

/**
 * Verifies that required indexes exist for all registered models.
 * Compares the indexes defined in Mongoose schemas against those present in
 * the database. Logs a warning for each model with missing indexes so that
 * operators know to run `npm run create-indexes -w packages/server`.
 */
async function verifyIndexes(): Promise<void> {
  try {
    const modelNames = mongoose.modelNames();
    let missingCount = 0;

    for (const modelName of modelNames) {
      const model = mongoose.model(modelName);
      const collection = model.collection;

      // Get indexes that Mongoose expects from the schema. `model.schema` is
      // typed loosely (`any`) by Mongoose, so cast to the known
      // `[keys, options]` tuple shape before calling `.indexes()` to keep this
      // fully type-safe without relying on eslint-disable directives.
      const schema = model.schema as {
        indexes: () => [Record<string, unknown>, Record<string, unknown>][];
      };
      const schemaIndexes = schema.indexes();
      if (schemaIndexes.length === 0) continue;

      // Get indexes that actually exist in the database
      let dbIndexes: { key: Record<string, unknown> }[];
      try {
        dbIndexes = await collection.indexes();
      } catch {
        // Collection may not exist yet (no documents created)
        logger.warn(
          `Collection "${collection.collectionName}" does not exist yet — indexes will be created when data is inserted or run "npm run create-indexes -w packages/server"`,
        );
        missingCount++;
        continue;
      }

      // Build a set of stringified index keys from the database
      const existingKeys = new Set(dbIndexes.map((idx) => JSON.stringify(idx.key)));

      // Check each schema-defined index
      for (const [fields] of schemaIndexes) {
        const key = JSON.stringify(fields);
        if (!existingKeys.has(key)) {
          missingCount++;
          logger.warn(
            `Missing index on "${collection.collectionName}": ${key} — run "npm run create-indexes -w packages/server"`,
          );
          // Only log the first missing index per model to avoid flooding
          break;
        }
      }
    }

    if (missingCount === 0) {
      logger.info('All database indexes verified');
    } else {
      logger.warn(
        `Found ${String(missingCount)} model(s) with missing indexes. Run "npm run create-indexes -w packages/server" to create them.`,
      );
    }
  } catch (error: unknown) {
    // Non-fatal — log and continue. The server can still operate without indexes
    // (just with degraded query performance).
    const message = error instanceof Error ? error.message : 'Unknown error';
    logger.warn(`Index verification failed: ${message}`);
  }
}

export async function connectDatabase(): Promise<typeof mongoose> {
  let retryCount = 0;

  mongoose.connection.on('connected', () => {
    logger.info('MongoDB connected successfully');
  });

  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected');
  });

  mongoose.connection.on('error', (error: unknown) => {
    logger.error('MongoDB connection error', { error });
  });

  mongoose.connection.on('reconnected', () => {
    logger.info('MongoDB reconnected');
  });

  const connect = async (): Promise<typeof mongoose> => {
    try {
      const connection = await mongoose.connect(config.MONGODB_URI, {
        autoIndex: config.NODE_ENV !== 'production',
        maxPoolSize: config.MONGO_MAX_POOL_SIZE,
        minPoolSize: config.MONGO_MIN_POOL_SIZE,
        socketTimeoutMS: 45000,
        serverSelectionTimeoutMS: 5000,
        heartbeatFrequencyMS: 10000,
      });

      // Surface a warning if the URI advertises a replica set but the connected
      // server doesn't expose one. Nothing falls back in that case: every
      // transactional endpoint throws at `withTransaction` and answers 500, so
      // the boot-time warning is the only notice an operator gets.
      await verifyTopology();

      // In production, autoIndex is disabled so indexes must be created manually.
      // Check for missing indexes and warn if any are found.
      if (config.NODE_ENV === 'production') {
        await verifyIndexes();
      }

      return connection;
    } catch (error: unknown) {
      retryCount++;
      if (retryCount >= MAX_RETRY_ATTEMPTS) {
        logger.error(`Failed to connect after ${String(MAX_RETRY_ATTEMPTS)} attempts. Giving up.`);
        throw error;
      }

      logger.warn(
        `Connection attempt ${String(retryCount)} failed. Retrying in ${String(RETRY_DELAY_MS)}ms...`,
      );
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
      return connect();
    }
  };

  return connect();
}

export async function disconnectDatabase(): Promise<void> {
  try {
    await mongoose.disconnect();
    logger.info('MongoDB disconnected gracefully');
  } catch (error: unknown) {
    logger.error('Error during database disconnection', { error });
    throw error;
  }
}
