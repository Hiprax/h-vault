/**
 * Terminal output for the local pipeline.
 *
 * Colour is opt-out (NO_COLOR / not a TTY) rather than opt-in, and every symbol
 * degrades to ASCII on a console that cannot render the Unicode glyphs — a git
 * hook's output is the only feedback a `git push` gives, so it has to survive
 * cmd.exe as readably as it survives a modern terminal.
 */
const noColor = Boolean(process.env['NO_COLOR']) || !process.stdout.isTTY;

const wrap = (open, close) => (text) => (noColor ? text : `[${open}m${text}[${close}m`);

export const color = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
};

/** cmd.exe's default code page renders these as garbage; fall back to ASCII. */
const unicodeOk = process.platform !== 'win32' || Boolean(process.env['WT_SESSION']);

export const symbol = {
  pass: unicodeOk ? '✔' : '+',
  fail: unicodeOk ? '✖' : 'x',
  skip: unicodeOk ? '─' : '-',
  run: unicodeOk ? '▶' : '>',
};

/** `93.4s` / `2m 07s` — durations a human can compare at a glance. */
export function formatDuration(ms) {
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = Math.round(seconds % 60);
  return `${String(minutes)}m ${String(rest).padStart(2, '0')}s`;
}

export function heading(text) {
  console.log(`\n${color.bold(color.blue(`${symbol.run} ${text}`))}`);
}

export function stepStart(index, total, title) {
  console.log(
    `\n${color.gray(`[${String(index)}/${String(total)}]`)} ${color.bold(color.cyan(title))}`,
  );
}

export function note(text) {
  console.log(color.gray(`      ${text}`));
}

export function warn(text) {
  console.log(color.yellow(`      ! ${text}`));
}

/** Prints the final PASS/FAIL/SKIP table. */
export function summary(results) {
  const width = Math.max(...results.map((r) => r.id.length), 10);
  console.log(`\n${color.bold('─'.repeat(width + 34))}`);
  console.log(color.bold('  Local pipeline summary'));
  console.log(color.bold('─'.repeat(width + 34)));

  for (const result of results) {
    const id = result.id.padEnd(width);
    const time = color.gray(formatDuration(result.durationMs).padStart(8));
    if (result.status === 'pass') {
      console.log(`  ${color.green(symbol.pass)} ${id}  ${time}`);
    } else if (result.status === 'fail') {
      console.log(`  ${color.red(symbol.fail)} ${id}  ${time}  ${color.red(result.detail ?? '')}`);
    } else {
      console.log(
        `  ${color.yellow(symbol.skip)} ${id}  ${' '.repeat(8)}  ${color.yellow(`SKIPPED — ${result.detail ?? ''}`)}`,
      );
    }
  }
  console.log(color.bold('─'.repeat(width + 34)));
}
