import { describe, it, expect } from 'vitest';
import { parseQrScanRequest } from '../../src/sandbox/protocol';

/**
 * The frame's validator for a scan request.
 *
 * Nothing arriving on the port is touched before it has been through here, and
 * anything that does not parse is refused rather than coerced. What this one
 * enforces is narrow on purpose: the image is checked only for being an object,
 * because `instanceof` is the wrong spelling across a realm boundary and the
 * decoder has to narrow it properly anyway, where a failure has somewhere to be
 * reported. The `requestId` is the part that cannot be recovered later, because
 * without it a reply could not be matched to a request at all.
 */
describe('parseQrScanRequest', () => {
  it('accepts a well-formed request and echoes its parts', () => {
    const image = {};
    expect(parseQrScanRequest({ kind: 'qrScan', requestId: 4, image })).toEqual({
      kind: 'qrScan',
      requestId: 4,
      image,
    });
  });

  it.each([
    ['a non-object', 'nope'],
    ['null', null],
    ['another request kind', { kind: 'render', requestId: 1, image: {} }],
    ['a missing kind', { requestId: 1, image: {} }],
    ['a missing request id', { kind: 'qrScan', image: {} }],
    ['a non-numeric request id', { kind: 'qrScan', requestId: '1', image: {} }],
    ['a fractional request id', { kind: 'qrScan', requestId: 1.5, image: {} }],
    ['a request id past the safe range', { kind: 'qrScan', requestId: 2 ** 53, image: {} }],
    ['a missing image', { kind: 'qrScan', requestId: 1 }],
    ['a null image', { kind: 'qrScan', requestId: 1, image: null }],
    ['a primitive image', { kind: 'qrScan', requestId: 1, image: 42 }],
  ])('refuses %s', (_label, data) => {
    expect(parseQrScanRequest(data)).toBeNull();
  });

  it('does not answer a render or transform request', () => {
    // The three request kinds are disjoint, and a validator that accepted a
    // neighbour's message would let one job be answered by another's handler.
    expect(
      parseQrScanRequest({ kind: 'transform', text: 'x', ext: '', format: true, repair: false }),
    ).toBeNull();
  });
});
