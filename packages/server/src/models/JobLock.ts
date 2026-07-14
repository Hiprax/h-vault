import mongoose, { Schema, type Model, type Types } from 'mongoose';

export interface IJobLock {
  _id: Types.ObjectId;
  jobName: string;
  lockedBy: string;
  lockedAt: Date;
  expiresAt: Date;
}

const jobLockSchema = new Schema<IJobLock>(
  {
    jobName: { type: String, required: true, unique: true },
    lockedBy: { type: String, required: true },
    lockedAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
  },
  {
    collection: 'job_locks',
  },
);

jobLockSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const JobLock: Model<IJobLock> = mongoose.model<IJobLock>('JobLock', jobLockSchema);
