import {
  Bell,
  CircleDot,
  Clipboard,
  Clock,
  Database,
  Download,
  Eye,
  FileText,
  Folder,
  Gauge,
  KeyRound,
  Lock,
  Mail,
  Palette,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  ShieldCheck,
  Smartphone,
  Sparkles,
  StickyNote,
  Timer,
  TrendingUp,
  Upload,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import type { ReleaseChangeKind, ReleaseIcon } from '@hvault/shared';

/**
 * How release notes look: one picture per highlight icon name, one label, colour
 * class and picture per kind of change.
 *
 * The server sends icon names and kinds as plain strings (a tab on an older build
 * must still read a newer server's notes), so every lookup goes through
 * `Object.hasOwn`, never a bare index: a name such as `toString` would otherwise
 * resolve through the prototype. Anything unknown gets a neutral fallback.
 */

const ICONS: Record<ReleaseIcon, LucideIcon> = {
  sparkles: Sparkles,
  shield: ShieldCheck,
  key: KeyRound,
  lock: Lock,
  file: FileText,
  folder: Folder,
  clock: Clock,
  bell: Bell,
  gauge: Gauge,
  eye: Eye,
  scan: ScanLine,
  note: StickyNote,
  upload: Upload,
  download: Download,
  refresh: RefreshCw,
  server: Server,
  palette: Palette,
  search: Search,
  wrench: Wrench,
  smartphone: Smartphone,
  mail: Mail,
  clipboard: Clipboard,
  timer: Timer,
  database: Database,
};

export function releaseIconFor(name: string): LucideIcon {
  return Object.hasOwn(ICONS, name) ? ICONS[name as ReleaseIcon] : Sparkles;
}

export interface ReleaseKindVisual {
  /** What the kind is called on screen. */
  label: string;
  /** Sets `--release-kind` to this kind's colour token (`styles/globals.css`). */
  className: string;
  icon: LucideIcon;
}

const KINDS: Record<ReleaseChangeKind, ReleaseKindVisual> = {
  added: { label: 'New', className: 'release-kind-added', icon: Sparkles },
  improved: { label: 'Improved', className: 'release-kind-improved', icon: TrendingUp },
  changed: { label: 'Changed', className: 'release-kind-changed', icon: RefreshCw },
  fixed: { label: 'Fixed', className: 'release-kind-fixed', icon: Wrench },
  security: { label: 'Security', className: 'release-kind-security', icon: ShieldCheck },
};

const OTHER_KIND: ReleaseKindVisual = {
  label: 'Other',
  className: 'release-kind-other',
  icon: CircleDot,
};

export function releaseKindFor(kind: string): ReleaseKindVisual {
  return Object.hasOwn(KINDS, kind) ? KINDS[kind as ReleaseChangeKind] : OTHER_KIND;
}
