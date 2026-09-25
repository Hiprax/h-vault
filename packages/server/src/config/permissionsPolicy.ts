/**
 * The `Permissions-Policy` this server sends: one value for every response it
 * renders, and a stricter one for the isolated document. ONE definition of each.
 *
 * ## Why the application sends one at all
 *
 * Both nginx layers a deployment puts in front of Express (the inner one in the
 * `web` image and the host one `newapp` renders) carry the ecosystem's golden
 * header FLOOR: when the upstream sends no `Permissions-Policy`, they add the
 * golden curated one, and that one disables the camera along with every other
 * powerful feature. helmet sends none, so behind either layer every document this
 * server rendered arrived with `camera=()`, and the authenticator import's camera
 * scan (`services/totpImport/camera.ts`, which calls `getUserMedia` in the
 * top-level document) was refused before the browser ever asked the user.
 * Measured in Chromium: under `camera=()`, `getUserMedia` rejects with
 * `NotAllowedError` and `document.featurePolicy.allowsFeature('camera')` is
 * false; with the header absent or `camera=(self)`, the stream opens. The floor
 * yields to any value the upstream sends (the application owns per-request
 * policy, and the floor exists for what nothing else covers), so the remedy lives
 * here and not in either nginx configuration.
 *
 * ## What it says
 *
 * The golden curated list, feature for feature and in its own order, with one
 * change: the camera is allowed for THIS origin, because one feature of this
 * application needs it. `(self)` hands nothing to any other document: a frame is
 * only ever delegated a feature its embedder names in an `allow` attribute, and
 * the viewer's frame names none; and its origin is opaque, which `self` never
 * matches anyway. What the golden list leaves at the browser's default (clipboard
 * writes, which every copy button here relies on, among them) stays at the
 * default here too.
 *
 * `tests/permissions-policy.test.ts` holds both values against the golden floor
 * in `docker/nginx/nginx.conf` AND the host floor in
 * `docker/nginx/00-newapp-http.conf`, so a refresh of the golden list that adds
 * or removes a feature fails there instead of leaving this server a feature
 * behind the policy it is supposed to match.
 */

/**
 * For the isolated render document: the golden list unchanged, the camera denied
 * too. It never needs a device (the QR decoder inside it is handed frames the
 * host captured), and on the one document that runs third-party parsers over
 * untrusted bytes, the stricter value is the direction every other header of its
 * already takes. Sent by `createSandboxDocumentHandler`, which replaces the
 * application's value on that one response.
 */
export const SANDBOX_PERMISSIONS_POLICY =
  'accelerometer=(), camera=(), display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=(), xr-spatial-tracking=()';

/**
 * For everything else this server answers: the same list with the camera allowed
 * for this origin, for the authenticator import's camera scan. Set on every
 * response by `app.ts`, before any route and before the static mount, so the
 * copy of the application shell the service worker precaches carries it too: a
 * document the worker serves from its cache takes its policy from the cached
 * response's headers.
 */
export const APPLICATION_PERMISSIONS_POLICY =
  'accelerometer=(), camera=(self), display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=(), xr-spatial-tracking=()';
