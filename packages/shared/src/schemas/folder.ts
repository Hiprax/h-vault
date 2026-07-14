import { z } from 'zod';
import { objectIdSchema } from './common.js';
import { MAX_ENCRYPTED_NAME_LENGTH, MAX_SORT_ORDER } from '../constants/index.js';

// NOTE: Folder nesting depth (MAX_FOLDER_NESTING_DEPTH) is enforced server-side
// via $graphLookup aggregation because it requires traversing the database.
export const createFolderSchema = z.object({
  encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH),
  nameIv: z.string().min(1).max(24),
  nameTag: z.string().min(1).max(32),
  searchHash: z
    .string()
    .regex(/^[a-f0-9]{64}$/)
    .optional(),
  parentId: objectIdSchema.optional(),
  icon: z
    .string()
    .max(50)
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'Icon must contain only alphanumeric characters, hyphens, and underscores',
    )
    .optional(),
  color: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/, 'Color must be a valid hex color code (e.g. #ff0000)')
    .optional(),
  sortOrder: z.number().int().min(0).max(MAX_SORT_ORDER).default(0),
});

export const updateFolderSchema = z
  .object({
    encryptedName: z.string().min(1).max(MAX_ENCRYPTED_NAME_LENGTH).optional(),
    nameIv: z.string().min(1).max(24).optional(),
    nameTag: z.string().min(1).max(32).optional(),
    searchHash: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
    parentId: objectIdSchema.nullable().optional(),
    icon: z
      .string()
      .max(50)
      .regex(
        /^[a-zA-Z0-9_-]+$/,
        'Icon must contain only alphanumeric characters, hyphens, and underscores',
      )
      .optional(),
    color: z
      .string()
      .regex(/^#[0-9a-fA-F]{6}$/, 'Color must be a valid hex color code (e.g. #ff0000)')
      .optional(),
    sortOrder: z.number().int().min(0).max(MAX_SORT_ORDER).optional(),
  })
  .refine(
    (data) => {
      const hasName = data.encryptedName !== undefined;
      const hasNameIv = data.nameIv !== undefined;
      const hasNameTag = data.nameTag !== undefined;
      return hasName === hasNameIv && hasNameIv === hasNameTag;
    },
    { message: 'encryptedName, nameIv, and nameTag must all be provided together or all omitted' },
  );

export const deleteFolderQuerySchema = z.object({
  action: z.enum(['move', 'delete']).default('move'),
});

export const reorderFolderSchema = z.object({
  sortOrder: z.number().int().min(0).max(MAX_SORT_ORDER),
});
