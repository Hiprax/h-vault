/**
 * The operator's invitation command (`npm run invite -- <email>`), driven through
 * `runInviteCli` against the suite's real database, plus its two-line entry point.
 *
 * What it must do: mint exactly one invitation for exactly the address given,
 * print the link once, keep only a hash of the token, and refuse (exit 1, no row)
 * anything that is not one address the domain allowlist admits.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { config } from '../src/config/index.js';
import { consoleIo, runInviteCli } from '../src/cli/inviteCli.js';

const mutableConfig = config as unknown as Record<string, unknown>;
const invitations = () => mongoose.connection.collection('invitations');

let saved: Record<string, unknown>;
let out: string[];
let err: string[];
const io = {
  log: (message: string) => out.push(message),
  error: (message: string) => err.push(message),
};

beforeEach(() => {
  saved = {
    REGISTRATION_MODE: mutableConfig.REGISTRATION_MODE,
    REGISTRATION_ALLOWED_DOMAINS: mutableConfig.REGISTRATION_ALLOWED_DOMAINS,
  };
  mutableConfig.REGISTRATION_MODE = 'invite';
  mutableConfig.REGISTRATION_ALLOWED_DOMAINS = [];
  out = [];
  err = [];
});

afterEach(() => {
  Object.assign(mutableConfig, saved);
});

describe('invite <email>', () => {
  it('mints one operator invitation for the address, prints its link once and stores only a hash', async () => {
    const code = await runInviteCli(['Friend@Example.org'], io);

    expect(code).toBe(0);
    expect(err).toEqual([]);
    const links = out.filter((line) => line.includes('#invite='));
    expect(links).toHaveLength(1);
    expect(links[0]!.startsWith(`${config.APP_URL}/register#invite=`)).toBe(true);
    const token = links[0]!.split('#invite=')[1]!;

    const rows = await invitations().find({}).toArray();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.email).toBe('friend@example.org');
    // An operator invitation belongs to no account.
    expect(rows[0]?.userId).toBeNull();
    expect(JSON.stringify(rows[0])).not.toContain(token);
  });

  it('warns, and still mints, when the server is not in invite mode yet', async () => {
    mutableConfig.REGISTRATION_MODE = 'open';
    const code = await runInviteCli(['early@example.org'], io);
    expect(code).toBe(0);
    expect(err.join('\n')).toMatch(/REGISTRATION_MODE is open/);
    expect(await invitations().countDocuments({})).toBe(1);
  });

  it('refuses an address outside the domain allowlist with exit 1 and no row', async () => {
    mutableConfig.REGISTRATION_ALLOWED_DOMAINS = ['example.org'];
    const code = await runInviteCli(['someone@example.com'], io);
    expect(code).toBe(1);
    expect(err.join('\n')).toMatch(/Could not create the invitation/);
    expect(out.some((line) => line.includes('#invite='))).toBe(false);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it.each([
    ['no address', []],
    ['two addresses', ['a@example.org', 'b@example.org']],
  ])('refuses %s with the usage and exit 1', async (_label, argv) => {
    const code = await runInviteCli(argv, io);
    expect(code).toBe(1);
    expect(err.join('\n')).toMatch(/^Usage: invite <email>/);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('refuses something that is not an address with exit 1 and no row', async () => {
    const code = await runInviteCli(['not-an-address'], io);
    expect(code).toBe(1);
    expect(err).toEqual(['Not an e-mail address: not-an-address']);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('prints the usage for --help and mints nothing', async () => {
    const code = await runInviteCli(['--help'], io);
    expect(code).toBe(0);
    expect(out.join('\n')).toMatch(/^Usage: invite <email>/);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('connects and disconnects itself when the process has no connection', async () => {
    const connect = vi.spyOn(mongoose, 'connect').mockResolvedValue(mongoose);
    const disconnect = vi.spyOn(mongoose, 'disconnect').mockResolvedValue();
    const state = vi
      .spyOn(mongoose.connection, 'readyState', 'get')
      .mockReturnValue(mongoose.ConnectionStates.disconnected);
    try {
      // The mint itself runs on the suite's live connection: only the state read
      // is faked, so what is asserted is the open/close decision.
      const code = await runInviteCli(['solo@example.org'], io);
      expect(code).toBe(0);
      expect(connect).toHaveBeenCalledWith(config.MONGODB_URI, expect.any(Object));
      expect(disconnect).toHaveBeenCalledTimes(1);
    } finally {
      state.mockRestore();
      connect.mockRestore();
      disconnect.mockRestore();
    }
  });

  it('leaves a connection it did not open alone', async () => {
    const disconnect = vi.spyOn(mongoose, 'disconnect');
    try {
      expect(await runInviteCli(['kept@example.org'], io)).toBe(0);
      expect(disconnect).not.toHaveBeenCalled();
    } finally {
      disconnect.mockRestore();
    }
  });
});

describe('the terminal', () => {
  it('writes the link to stdout and a failure to stderr', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      consoleIo.log('the link');
      consoleIo.error('the failure');
      expect(log).toHaveBeenCalledWith('the link');
      expect(error).toHaveBeenCalledWith('the failure');
      expect(log).not.toHaveBeenCalledWith('the failure');
    } finally {
      log.mockRestore();
      error.mockRestore();
    }
  });
});

describe('the entry point', () => {
  it('runs the command with the process arguments and sets the exit code from it', async () => {
    const savedArgv = process.argv;
    const savedExitCode = process.exitCode;
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    process.argv = ['node', 'invite.js', '--help'];
    try {
      await import('../src/cli/invite.js');
      expect(process.exitCode).toBe(0);
      expect(String(log.mock.calls[0]?.[0])).toMatch(/^Usage: invite <email>/);
    } finally {
      process.argv = savedArgv;
      process.exitCode = savedExitCode;
      log.mockRestore();
    }
  });
});
