/**
 * Vault & Folder API service.
 *
 * All endpoints are relative to the Axios base URL (/api/v1).
 */

import type { AxiosResponse } from 'axios';
import type {
  ApiResponse,
  PaginatedResponse,
  IVaultItemResponse,
  IFolderResponse,
  CreateVaultItemInput,
  UpdateVaultItemInput,
  BulkReEncryptInput,
  CreateFolderInput,
  UpdateFolderInput,
} from '@hvault/shared';
import { api } from './client.js';

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

export interface ListItemsParams {
  page?: number;
  limit?: number;
  itemType?: string;
  folderId?: string;
  favorite?: boolean;
  trash?: boolean;
  sortBy?: 'createdAt' | 'updatedAt' | 'itemType';
  sortOrder?: 'asc' | 'desc';
}

// ---------------------------------------------------------------------------
// Vault Items
// ---------------------------------------------------------------------------

export function listItemsApi(
  params?: ListItemsParams,
): Promise<AxiosResponse<PaginatedResponse<IVaultItemResponse>>> {
  return api.get('/vault/items', { params });
}

export function getItemApi(id: string): Promise<AxiosResponse<ApiResponse<IVaultItemResponse>>> {
  return api.get(`/vault/items/${id}`);
}

export function createItemApi(
  data: CreateVaultItemInput,
): Promise<AxiosResponse<ApiResponse<IVaultItemResponse>>> {
  return api.post('/vault/items', data);
}

export function updateItemApi(
  id: string,
  data: UpdateVaultItemInput,
): Promise<AxiosResponse<ApiResponse<IVaultItemResponse>>> {
  return api.put(`/vault/items/${id}`, data);
}

export function deleteItemApi(id: string): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/vault/items/${id}`);
}

export function permanentDeleteApi(id: string): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/vault/items/${id}/permanent`);
}

export function restoreItemApi(
  id: string,
): Promise<AxiosResponse<ApiResponse<IVaultItemResponse>>> {
  return api.post(`/vault/items/restore/${id}`);
}

export function bulkDeleteApi(ids: string[]): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/vault/items/bulk-delete', { ids });
}

export function bulkMoveApi(
  ids: string[],
  folderId: string | null,
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/vault/items/bulk-move', { ids, folderId });
}

export interface ListTrashParams {
  page?: number;
  limit?: number;
  sortBy?: 'deletedAt' | 'createdAt' | 'updatedAt' | 'itemType';
  sortOrder?: 'asc' | 'desc';
}

export function listTrashApi(
  params?: ListTrashParams,
): Promise<AxiosResponse<PaginatedResponse<IVaultItemResponse>>> {
  return api.get('/vault/items/trash', { params });
}

export function emptyTrashApi(): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete('/vault/items/trash/empty');
}

export function bulkReEncryptApi(
  data: BulkReEncryptInput,
): Promise<AxiosResponse<ApiResponse<{ updatedCount: number }>>> {
  return api.post('/vault/items/bulk-reencrypt', data);
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

export function listFoldersApi(): Promise<AxiosResponse<ApiResponse<IFolderResponse[]>>> {
  return api.get('/folders');
}

export function createFolderApi(
  data: CreateFolderInput,
): Promise<AxiosResponse<ApiResponse<IFolderResponse>>> {
  return api.post('/folders', data);
}

export function updateFolderApi(
  id: string,
  data: UpdateFolderInput,
): Promise<AxiosResponse<ApiResponse<IFolderResponse>>> {
  return api.put(`/folders/${id}`, data);
}

export function reorderFolderApi(
  id: string,
  sortOrder: number,
): Promise<AxiosResponse<ApiResponse<IFolderResponse>>> {
  return api.put(`/folders/${id}/sort`, { sortOrder });
}

export function deleteFolderApi(
  id: string,
  action?: 'move' | 'delete',
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/folders/${id}`, { params: action ? { action } : undefined });
}
