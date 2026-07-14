declare module 'rate-limit-mongo' {
  import type { Store } from 'express-rate-limit';
  import type { MongoClient } from 'mongodb';

  interface MongoStoreOptions {
    uri?: string;
    client?: MongoClient;
    collectionName?: string;
    expireTimeMs?: number;
    resetExpireDateOnChange?: boolean;
    errorHandler?: (err: unknown) => void;
    createTtlIndex?: boolean;
    prefix?: string;
    collection?: unknown;
  }

  class MongoStore implements Store {
    constructor(options: MongoStoreOptions);
    init(options: { windowMs: number }): void;
    increment(key: string): Promise<{ totalHits: number; resetTime: Date | undefined }>;
    decrement(key: string): Promise<void>;
    resetKey(key: string): Promise<void>;
  }

  export default MongoStore;
}
