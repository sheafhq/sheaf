// Secret scrubber. Prevents Sheaf API keys from leaking into stdout,
// stderr, console.error, or any serialized error output.
//
// Added 2026-11-12 after a WP6 smoke test printed a real sk_live_ key into
// the session transcript. The prefix was also renamed sk_live_ → shf_live_
// so new keys are not mistaken for Stripe secret keys when grep'd.
//
// Scope: patterns that look like Sheaf API keys. Does NOT touch anything
// else (not Ethereum addresses, not UUIDs, not account_ids by themselves).

const KEY_PATTERNS: RegExp[] = [
  // Current + legacy Sheaf key formats. 32+ hex chars after the prefix.
  /\bshf_(?:live|test)_[a-f0-9]{32,}\b/g,
  /\bsk_(?:live|test)_[a-f0-9]{32,}\b/g,
];

const REDACTED = "[REDACTED_SHEAF_KEY]";

/** Replace any Sheaf-key-shaped substring with [REDACTED_SHEAF_KEY]. Safe
 *  on any input type — stringifies first. Idempotent. */
export function scrubSecrets(input: unknown): string {
  let s: string;
  if (typeof input === "string") s = input;
  else if (input === null || input === undefined) s = String(input);
  else if (typeof input === "object") {
    try {
      s = JSON.stringify(input);
    } catch {
      s = String(input);
    }
  } else {
    s = String(input);
  }
  for (const re of KEY_PATTERNS) s = s.replace(re, REDACTED);
  return s;
}

/** Scrub each argument individually. Preserves non-string types where
 *  possible so printf-style formatting still works on primitives. */
function scrubArgs(args: unknown[]): unknown[] {
  return args.map((a) => {
    if (typeof a === "string") return scrubSecrets(a);
    if (a instanceof Error) {
      const e = new Error(scrubSecrets(a.message));
      e.stack = a.stack ? scrubSecrets(a.stack) : undefined;
      return e;
    }
    if (typeof a === "object" && a !== null) return scrubSecrets(a);
    return a;
  });
}

let installed = false;

/** Install global wrappers around console.log, console.error, console.warn,
 *  console.info, process.stdout.write, process.stderr.write. Idempotent. */
export function installGlobalScrubber(): void {
  if (installed) return;
  installed = true;

  const wrap =
    (orig: (...a: unknown[]) => void) =>
    (...args: unknown[]) =>
      orig(...scrubArgs(args));
  console.log = wrap(console.log);
  console.error = wrap(console.error);
  console.warn = wrap(console.warn);
  console.info = wrap(console.info);

  // Wrap stdout/stderr .write to scrub string chunks. Node's write()
  // overloads (Buffer | string, encoding?, cb?) are too fiddly to re-express
  // cleanly, so we route all paths through a single untyped shim.
  const wrapStream = (stream: NodeJS.WritableStream): void => {
    const origWrite = stream.write.bind(stream) as (
      ...args: unknown[]
    ) => boolean;
    const wrapped = (chunk: unknown, ...rest: unknown[]): boolean => {
      let out: unknown = chunk;
      if (typeof chunk === "string") out = scrubSecrets(chunk);
      else if (chunk && typeof (chunk as { toString?: () => string }).toString === "function") {
        try {
          const asStr = (chunk as { toString: () => string }).toString();
          for (const re of KEY_PATTERNS) re.lastIndex = 0;
          if (KEY_PATTERNS.some((re) => re.test(asStr))) {
            out = scrubSecrets(asStr);
          }
        } catch {}
        for (const re of KEY_PATTERNS) re.lastIndex = 0;
      }
      return origWrite(out, ...rest);
    };
    (stream as unknown as { write: typeof wrapped }).write = wrapped;
  };
  wrapStream(process.stdout);
  wrapStream(process.stderr);

  // Final safety net: any unhandled error path.
  process.on("uncaughtException", (err) => {
    console.error("[sheaf] uncaught:", scrubSecrets(err.stack ?? err.message));
    process.exit(1);
  });
  process.on("unhandledRejection", (reason) => {
    console.error("[sheaf] unhandled:", scrubSecrets(String(reason)));
    process.exit(1);
  });
}

/** For tests: forcibly reset the installed flag so a test can re-install
 *  with freshly-wrapped originals. Not exported in the public barrel. */
export function _resetInstalledForTest(): void {
  installed = false;
}
