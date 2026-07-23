/**
 * Tests for the shared client download helpers (`lib/download.ts`).
 *
 * Covers, per Phase 3 acceptance:
 *  - `downloadBlob` builds an object URL from the Blob, points a synthetic
 *    `<a download>` at it with the right filename, clicks it, and revokes the URL.
 *  - The object URL is ALWAYS revoked — including when `click()` throws (the
 *    `finally` branch), in which case the error still propagates.
 *  - `downloadText` wraps the text in a Blob with the passed MIME type and
 *    delegates to `downloadBlob` (filename + always-revoke inherited).
 *
 * Uses the established `vi.stubGlobal('URL', {...})` + `HTMLAnchorElement`
 * click-spy idiom from the FileEncryptPanel/FileDecryptPanel tests.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { downloadBlob, downloadText } from '../src/lib/download';

describe('lib/download', () => {
  let createObjectURL: ReturnType<typeof vi.fn>;
  let revokeObjectURL: ReturnType<typeof vi.fn>;
  let createdAnchors: HTMLAnchorElement[];
  let createElementSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    createObjectURL = vi.fn(() => 'blob:mock-url');
    revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });

    // Capture every anchor the helper creates so we can assert href/download.
    createdAnchors = [];
    const realCreateElement = document.createElement.bind(document);
    createElementSpy = vi
      .spyOn(document, 'createElement')
      .mockImplementation((tagName: string, options?: ElementCreationOptions) => {
        const el = realCreateElement(tagName, options);
        if (tagName === 'a') createdAnchors.push(el as HTMLAnchorElement);
        return el;
      });
  });

  afterEach(() => {
    createElementSpy.mockRestore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('downloadBlob', () => {
    it('creates an object URL, wires an anchor, clicks it, and revokes the URL', () => {
      const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
      const blob = new Blob(['hello'], { type: 'text/plain' });

      downloadBlob(blob, 'greeting.txt');

      expect(createObjectURL).toHaveBeenCalledWith(blob);
      expect(createdAnchors).toHaveLength(1);
      const anchor = createdAnchors[0]!;
      expect(anchor.download).toBe('greeting.txt');
      // jsdom resolves the href against the document base; assert the raw value.
      expect(anchor.getAttribute('href')).toBe('blob:mock-url');
      expect(clickSpy).toHaveBeenCalledTimes(1);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
    });

    it('revokes the object URL even when the anchor click throws, and rethrows', () => {
      const boom = new Error('click failed');
      const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {
        throw boom;
      });
      const blob = new Blob(['x'], { type: 'text/plain' });

      expect(() => {
        downloadBlob(blob, 'x.txt');
      }).toThrow(boom);

      expect(clickSpy).toHaveBeenCalledTimes(1);
      // The `finally` branch must still have revoked the URL despite the throw.
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
    });
  });

  describe('downloadText', () => {
    it('wraps the text in a Blob with the given MIME type and downloads it', async () => {
      vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

      downloadText('{"a":1}', 'data.json', 'application/json');

      expect(createObjectURL).toHaveBeenCalledTimes(1);
      const blob = createObjectURL.mock.calls[0]![0] as Blob;
      expect(blob).toBeInstanceOf(Blob);
      expect(blob.type).toBe('application/json');
      expect(await blob.text()).toBe('{"a":1}');

      expect(createdAnchors[0]!.download).toBe('data.json');
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:mock-url');
    });

    it('passes a distinct MIME type through to the Blob (text/csv)', () => {
      vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

      downloadText('a,b\r\n1,2', 'sheet.csv', 'text/csv');

      const blob = createObjectURL.mock.calls[0]![0] as Blob;
      expect(blob.type).toBe('text/csv');
      expect(createdAnchors[0]!.download).toBe('sheet.csv');
    });
  });
});
