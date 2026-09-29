#!/usr/bin/env node
/**
 * The entry point of the operator's invitation command. Everything it does is
 * `runInviteCli`'s (`cli/inviteCli.ts`), which the suite drives directly.
 */
import { consoleIo, runInviteCli } from './inviteCli.js';

process.exitCode = await runInviteCli(process.argv.slice(2), consoleIo);
