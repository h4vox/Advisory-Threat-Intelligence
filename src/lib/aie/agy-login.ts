/**
 * Antigravity CLI (`agy`) sign-in, driven through the real CLI inside the sandbox container.
 *
 * The CLI owns the OAuth flow: it builds Google's authorization URL with its own OAuth client and
 * exchanges the code itself. AIE only relays. It runs `agy` in a pseudo-terminal, picks "Google OAuth"
 * in the CLI's login menu, shows the user the URL the CLI printed, and types back the authorization
 * code the user pastes. (The previous flow built that URL in-app without a client_id, which Google
 * rejected with "Missing required parameter: client_id".)
 *
 * This module has no server-only imports: the terminal and the post-sign-in verification are injected,
 * so the state machine is tested against a simulated CLI in a real pseudo-terminal.
 */

export type AgyLoginState =
  | "starting"
  | "choosing_method"
  | "awaiting_code"
  | "signing_in"
  | "verifying"
  | "signed_in"
  | "failed"
  | "cancelled";

export type AgyLoginSnapshot = {
  id: string;
  state: AgyLoginState;
  /** Google authorization URL printed by the CLI (validated: accounts.google.com, OAuth path, client_id). */
  authUrl: string | null;
  /** One line for the UI. */
  message: string;
  /** Recent terminal output, escape codes removed and the authorization code redacted. */
  transcript: string;
  /** The CLI showed no login screen and the account already answers prompts. */
  alreadySignedIn: boolean;
  startedAt: number;
  updatedAt: number;
};

/** The pseudo-terminal running `agy`, as the session sees it. */
export type LoginTerminal = {
  write(data: string): void;
  onData(listener: (chunk: string) => void): void;
  onExit(listener: (code: number | null) => void): void;
  kill(): void;
};

export type LoginVerifier = () => Promise<{ ok: boolean; detail: string }>;

export type LoginTimings = {
  /** Output must be quiet this long before a frame is read (terminal UIs redraw in bursts). */
  settleMs: number;
  /** Delay between synthetic key presses. */
  keyDelayMs: number;
  /** No login screen after this long: the CLI may already be signed in, so verify. */
  alreadySignedInMs: number;
  /** After the code is typed, the screen must stop showing "Signing in…" this long (no error) before verifying. */
  signInSettleMs: number;
  /** How often the signing-in screen is re-read. */
  signInPollMs: number;
  /** After the code is typed, verify no later than this regardless. */
  signInTimeoutMs: number;
  /** How long the URL stays valid for the user to paste a code back. */
  codeWaitMs: number;
};

export const DEFAULT_LOGIN_TIMINGS: LoginTimings = {
  settleMs: 250,
  keyDelayMs: 120,
  alreadySignedInMs: 12_000,
  signInSettleMs: 2_500,
  signInPollMs: 500,
  signInTimeoutMs: 120_000,
  codeWaitMs: 10 * 60_000,
};

const MAX_RAW_BYTES = 256 * 1024;
const TRANSCRIPT_CHARS = 6000;
const KEY_DOWN = "\x1b[B";
const KEY_UP = "\x1b[A";
const KEY_ENTER = "\r";
const KEY_CTRL_C = "\x03";

// ---------------------------------------------------------------------------
// Terminal text helpers (pure)
// ---------------------------------------------------------------------------

/** Plain text of terminal output: escape sequences removed, carriage-return redraws as new lines. */
export function stripTerminal(raw: string): string {
  return (
    raw
      // OSC (window title, OSC 8 hyperlinks): ESC ] ... BEL | ESC \
      .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
      // CSI (colours, cursor moves, erase)
      .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
      // Remaining two-character escapes
      .replace(/\x1b[@-Z\\-_]/g, "")
      // A PTY maps "\n" to "\r\n" (onlcr), so a program's "\r\n" arrives as "\r\r\n": one line break.
      .replace(/\r*\n/g, "\n")
      // A lone carriage return redraws the line (spinners): keep each frame on its own line.
      .replace(/\r/g, "\n")
      // Other control characters except tab and newline
      .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "")
      .replace(/[ \t]+$/gm, "")
      .replace(/\n{3,}/g, "\n\n")
  );
}

/**
 * Only a genuine Google OAuth authorization URL is ever shown to the user. Terminal output is
 * untrusted, so this rejects lookalike hosts, non-HTTPS URLs and URLs without an OAuth client.
 */
export function isGoogleAuthUrl(candidate: string): boolean {
  let u: URL;
  try {
    u = new URL(candidate);
  } catch {
    return false;
  }
  return (
    u.protocol === "https:" &&
    u.hostname === "accounts.google.com" &&
    u.port === "" &&
    u.username === "" &&
    /^\/o\/oauth2(?:\/v2)?\/auth\/?$/.test(u.pathname) &&
    Boolean(u.searchParams.get("client_id")) &&
    Boolean(u.searchParams.get("redirect_uri")) &&
    u.searchParams.get("response_type") === "code"
  );
}

const URL_CHARS = /^[A-Za-z0-9%._~:/?#[\]@!$&'()*+,;=-]+$/;

/**
 * The authorization URL the CLI printed. Prefers the OSC 8 hyperlink target (never wrapped by the
 * terminal); otherwise re-joins a URL the terminal wrapped across lines. Latest occurrence wins.
 */
export function extractAuthUrl(raw: string): string | null {
  const osc8 = [...raw.matchAll(/\x1b\]8;[^;\x07\x1b]*;(https:\/\/accounts\.google\.com\/[^\x07\x1b\s]+)(?:\x07|\x1b\\)/g)];
  for (let i = osc8.length - 1; i >= 0; i--) {
    if (isGoogleAuthUrl(osc8[i][1])) return osc8[i][1];
  }
  const lines = stripTerminal(raw).split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const at = lines[i].indexOf("https://accounts.google.com/");
    if (at < 0) continue;
    let url = lines[i].slice(at).trim().split(/\s+/)[0];
    for (let j = i + 1; j < lines.length; j++) {
      const next = lines[j].trim();
      if (!next || !URL_CHARS.test(next)) break;
      url += next;
    }
    if (isGoogleAuthUrl(url)) return url;
  }
  return null;
}

export type LoginMenu = { options: string[]; selected: number; googleIndex: number };

/** The CLI's "Select login method" menu as last drawn, or null when it is not on screen. */
export function parseLoginMenu(text: string): LoginMenu | null {
  const at = text.lastIndexOf("login method");
  if (at < 0) return null;
  const options: string[] = [];
  let selected = -1;
  for (const line of text.slice(at).split("\n").slice(1)) {
    const m = /^\s*([>❯›▸➤*])?\s*\d+[.)]\s+(.+?)\s*$/.exec(line);
    if (m) {
      if (m[1]) selected = options.length;
      options.push(m[2]);
      continue;
    }
    if (options.length > 0 && line.trim()) break; // the hint line after the options
  }
  const googleIndex = options.findIndex((o) => /google\s*oauth/i.test(o));
  if (options.length === 0 || googleIndex < 0) return null;
  return { options, selected: selected < 0 ? 0 : selected, googleIndex };
}

/**
 * The authorization code to type into the CLI. Accepts the code itself or the full redirect URL
 * containing `code=`. Anything that is not a plain code is refused: the value is written to a
 * terminal, so a newline or escape sequence would inject key presses into the CLI.
 */
export function normalizeAuthCode(input: string): { ok: true; code: string } | { ok: false; error: string } {
  let code = String(input ?? "").trim();
  if (/[?&]code=/.test(code)) {
    try {
      const u = new URL(code.startsWith("http") ? code : `https://x.invalid/${code.replace(/^[/?]+/, "?")}`);
      code = u.searchParams.get("code") ?? code;
    } catch {
      /* not a URL: validated below */
    }
  }
  if (/%[0-9a-f]{2}/i.test(code)) {
    try {
      code = decodeURIComponent(code);
    } catch {
      return { ok: false, error: "The code contains malformed percent-encoding." };
    }
  }
  if (code.length < 8 || code.length > 512) return { ok: false, error: "That does not look like an authorization code." };
  if (!/^[A-Za-z0-9/_.~+=-]+$/.test(code)) return { ok: false, error: "The code can only contain letters, numbers and / _ . ~ + = -" };
  return { ok: true, code };
}

const ERROR_LINE = /\b(?:error|invalid|failed|failure|denied|expired|unauthori[sz]ed|forbidden|not allowed|try again)\b/i;
const SUCCESS_LINE = /\b(?:signed in|logged in|authenticated|login successful|welcome back)\b/i;

/** True while the latest screen still shows the CLI working (spinner or "Signing in…"). */
export function isBusyScreen(text: string): boolean {
  const tail = text.split("\n").map((l) => l.trim()).filter(Boolean).slice(-4);
  return tail.some((l) => /^[\u2800-\u28ff]/.test(l) || /\b(?:signing in|authenticating|exchanging|verifying|please wait|loading)\b/i.test(l));
}

const SETUP_SCREEN =
  /\b(?:choose your colou?r scheme|(?:choose|select|pick) (?:a |your )?(?:colou?r )?theme|enter\s+confirm|press enter to (?:continue|confirm)|do you trust|trust (?:this|the) (?:folder|directory|workspace|files)|get started|terms of service|usage statistics|send (?:anonymous )?(?:usage|telemetry))\b|\[\s*(?:next|continue|ok|accept)\s*\]/i;

/**
 * True when the latest screen is one of the CLI's first-run setup steps (colour scheme, folder
 * trust, terms, telemetry): a selector or prompt that Enter accepts with its default. Never the
 * login-method menu, which is answered by choosing Google OAuth.
 */
export function isSetupScreen(text: string): boolean {
  const tail = text.split("\n").slice(-60).join("\n");
  return SETUP_SCREEN.test(tail) && !/login method/i.test(tail);
}

/** First line that reports a sign-in error, if any. */
export function findErrorLine(text: string): string | null {
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (t && ERROR_LINE.test(t) && !/paste the authorization code/i.test(t)) return t.slice(0, 240);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

const MESSAGES: Record<AgyLoginState, string> = {
  starting: "Starting the Antigravity CLI in the sandbox…",
  choosing_method: "Selecting Google OAuth sign-in…",
  awaiting_code: "Open the Google sign-in link, approve access, then paste the authorization code here.",
  signing_in: "Signing in…",
  verifying: "Checking that the agent can answer…",
  signed_in: "Signed in. The agent is ready.",
  failed: "Sign-in failed.",
  cancelled: "Sign-in cancelled.",
};

const TERMINAL: ReadonlySet<AgyLoginState> = new Set(["signed_in", "failed", "cancelled"]);

export class AgyLoginSession {
  readonly id: string;
  private readonly spawnTerminal: () => LoginTerminal;
  private readonly verify: LoginVerifier;
  private readonly t: LoginTimings;
  private readonly now: () => number;
  private readonly onChange?: (snapshot: AgyLoginSnapshot) => void;

  private term: LoginTerminal | null = null;
  private raw = "";
  private state: AgyLoginState = "starting";
  private message = MESSAGES.starting;
  private authUrl: string | null = null;
  private alreadySignedIn = false;
  private submittedCode: string | null = null;
  /** Raw-buffer offset when the code was typed: only output after it decides the outcome. */
  private codeOffset = 0;
  private menuChosen = false;
  private startedAt = 0;
  private updatedAt = 0;
  /** Throttle (not debounce) so a continuously animating spinner cannot starve evaluation. */
  private evalTimer: ReturnType<typeof setTimeout> | null = null;
  private phaseTimer: ReturnType<typeof setTimeout> | null = null;
  private signInPoll: ReturnType<typeof setInterval> | null = null;
  private codeAt = 0;
  private lastBusyAt = 0;
  /** First-run setup screens answered with Enter: how many, when, and where the output stood. */
  private setupPresses = 0;
  private lastSetupPressAt = 0;
  private setupOffset = 0;
  private keyTimers: ReturnType<typeof setTimeout>[] = [];
  /** Each verification run gets a generation; a result from an abandoned run is ignored. */
  private verifyGen = 0;
  private verifyingFromStartup = false;

  constructor(deps: {
    spawn: () => LoginTerminal;
    verify: LoginVerifier;
    timings?: Partial<LoginTimings>;
    now?: () => number;
    id?: string;
    /** Called after every state change (not for terminal output), e.g. to persist a finished sign-in. */
    onChange?: (snapshot: AgyLoginSnapshot) => void;
  }) {
    this.spawnTerminal = deps.spawn;
    this.verify = deps.verify;
    this.onChange = deps.onChange;
    this.t = { ...DEFAULT_LOGIN_TIMINGS, ...deps.timings };
    this.now = deps.now ?? Date.now;
    this.id = deps.id ?? `agylogin_${Math.random().toString(36).slice(2, 10)}`;
  }

  start(): AgyLoginSnapshot {
    this.startedAt = this.now();
    this.touch();
    let term: LoginTerminal;
    try {
      term = this.spawnTerminal();
    } catch (err) {
      this.fail(`Could not start the Antigravity CLI: ${err instanceof Error ? err.message : String(err)}`);
      return this.snapshot();
    }
    this.term = term;
    term.onData((chunk) => this.onData(chunk));
    term.onExit((code) => this.onExit(code));
    // No login screen within the window: the CLI may already be signed in. If a login screen shows
    // up while that check runs, the check is abandoned and sign-in continues normally.
    this.armPhaseTimer(this.t.alreadySignedInMs, () => {
      if (this.state === "starting") void this.runVerification(true);
    });
    return this.snapshot();
  }

  /** Types the user's authorization code into the CLI. */
  submitCode(input: string): { ok: true } | { ok: false; error: string } {
    if (this.state !== "awaiting_code") return { ok: false, error: "Sign-in is not waiting for a code. Start sign-in again." };
    const parsed = normalizeAuthCode(input);
    if (!parsed.ok) return parsed;
    this.submittedCode = parsed.code;
    this.codeOffset = this.raw.length;
    this.setState("signing_in");
    this.sendKeys([parsed.code, KEY_ENTER]);
    this.codeAt = this.now();
    this.lastBusyAt = 0;
    // Re-read the screen until the CLI stops showing "Signing in…", then verify for real.
    this.signInPoll = setInterval(() => this.pollSignIn(), this.t.signInPollMs);
    this.signInPoll.unref?.();
    this.armPhaseTimer(this.t.signInTimeoutMs, () => {
      if (this.state === "signing_in") void this.runVerification(false, true);
    });
    return { ok: true };
  }

  cancel(): AgyLoginSnapshot {
    if (!TERMINAL.has(this.state)) {
      this.verifyGen++;
      this.setState("cancelled");
      this.close();
    }
    return this.snapshot();
  }

  isFinished(): boolean {
    return TERMINAL.has(this.state);
  }

  snapshot(): AgyLoginSnapshot {
    return {
      id: this.id,
      state: this.state,
      authUrl: this.state === "awaiting_code" || this.state === "signing_in" ? this.authUrl : null,
      message: this.message,
      transcript: this.transcript(),
      alreadySignedIn: this.alreadySignedIn,
      startedAt: this.startedAt,
      updatedAt: this.updatedAt,
    };
  }

  // -------------------------------------------------------------------------

  private transcript(): string {
    let text = stripTerminal(this.raw.slice(-MAX_RAW_BYTES));
    if (this.submittedCode) text = text.split(this.submittedCode).join("••••••••");
    return text.length > TRANSCRIPT_CHARS ? text.slice(-TRANSCRIPT_CHARS) : text;
  }

  private onData(chunk: string) {
    if (TERMINAL.has(this.state)) return;
    this.raw += chunk;
    if (this.raw.length > MAX_RAW_BYTES * 2) {
      const cut = this.raw.length - MAX_RAW_BYTES;
      this.raw = this.raw.slice(cut);
      this.codeOffset = Math.max(0, this.codeOffset - cut);
    }
    this.touch();
    if (!this.evalTimer) {
      this.evalTimer = setTimeout(() => {
        this.evalTimer = null;
        this.evaluate();
      }, this.t.settleMs);
    }
  }

  /** Reads the screen and moves the flow forward. */
  private evaluate() {
    if (TERMINAL.has(this.state)) return;

    const loginPhase = this.state === "starting" || this.state === "choosing_method" || (this.state === "verifying" && this.verifyingFromStartup);
    if (loginPhase) {
      const url = extractAuthUrl(this.raw);
      const menu = url ? null : parseLoginMenu(stripTerminal(this.raw));
      if ((url || menu) && this.state === "verifying") {
        // The CLI is not signed in after all: drop the startup check and continue the sign-in.
        this.verifyGen++;
        this.verifyingFromStartup = false;
      }
      if (url) {
        this.authUrl = url;
        this.setState("awaiting_code");
        this.armPhaseTimer(this.t.codeWaitMs, () => {
          if (this.state === "awaiting_code") this.fail("The sign-in link expired before a code was entered. Start sign-in again.");
        });
        return;
      }
      // A setup screen (first run) before or after the login menu: accept its default and keep going.
      if ((!menu || this.menuChosen) && this.answerSetupScreen(stripTerminal(this.raw.slice(-MAX_RAW_BYTES)))) return;
      if (menu) {
        if (this.state === "verifying") this.setState("starting");
        if (!this.menuChosen) {
          this.menuChosen = true;
          this.setState("choosing_method");
          const moves = menu.googleIndex - menu.selected;
          this.sendKeys([...Array<string>(Math.abs(moves)).fill(moves > 0 ? KEY_DOWN : KEY_UP), KEY_ENTER]);
        }
      }
      return;
    }

    if (this.state === "signing_in") this.pollSignIn();
  }

  /**
   * Output since the code was typed (or since the last setup screen was answered), with the code
   * removed. Setup screens draw sample text ("✗ error: compilation failed" in the colour-scheme
   * preview), so what came before the last answered one is never read as a sign-in error.
   */
  private outputSinceCode(): string {
    const after = stripTerminal(this.raw.slice(Math.max(this.codeOffset, this.setupOffset)));
    return this.submittedCode ? after.split(this.submittedCode).join("") : after;
  }

  /**
   * Answers a first-run setup screen with Enter (its default), at most once per new screen and 12
   * times in all. Returns true while a setup screen is showing, so the caller keeps waiting.
   */
  private answerSetupScreen(visible: string): boolean {
    if (!isSetupScreen(visible)) return false;
    const now = this.now();
    if (this.setupPresses < 12 && now - this.lastSetupPressAt >= Math.max(this.t.settleMs * 3, 600) && this.raw.length > this.setupOffset) {
      this.setupPresses++;
      this.lastSetupPressAt = now;
      this.setupOffset = this.raw.length;
      if (this.state === "signing_in") this.message = "Signed in. Finishing the CLI's first-run setup…";
      this.sendKeys([KEY_ENTER]);
    }
    this.lastBusyAt = now; // not settled while the CLI asks something
    return true;
  }

  /** Fails on a CLI error or a return to the login screen. Returns true when it failed the session. */
  private failOnSignInError(visible: string): boolean {
    const error = findErrorLine(visible);
    if (error) {
      this.fail(`The CLI rejected the code: ${error}`);
      return true;
    }
    if (parseLoginMenu(visible)) {
      this.fail("The CLI did not accept the sign-in and returned to its login screen. Start sign-in again.");
      return true;
    }
    return false;
  }

  /**
   * Signing-in phase: fail fast on an error; verify once the CLI reports success, or once its screen
   * has stopped showing "Signing in…" for the settle window. A slow token exchange keeps waiting.
   */
  private pollSignIn() {
    if (this.state !== "signing_in") return;
    const visible = this.outputSinceCode();
    if (this.answerSetupScreen(visible)) return;
    if (this.failOnSignInError(visible)) return;
    const now = this.now();
    if (isBusyScreen(visible)) this.lastBusyAt = now;
    if (SUCCESS_LINE.test(visible) || now - Math.max(this.codeAt, this.lastBusyAt) >= this.t.signInSettleMs) {
      void this.runVerification(false);
    }
  }

  private onExit(code: number | null) {
    this.term = null;
    if (TERMINAL.has(this.state)) return;
    // Some CLIs exit right after a successful sign-in: let the verifier decide (no retries now).
    if (this.state === "signing_in") {
      if (!this.failOnSignInError(this.outputSinceCode())) void this.runVerification(false, true);
      return;
    }
    if (this.state === "verifying") return; // the running check decides
    const tail = this.transcript().trim().split("\n").filter(Boolean).slice(-3).join(" · ");
    this.fail(`The Antigravity CLI exited (code ${code ?? "?"}) before sign-in finished.${tail ? ` Last output: ${tail}` : ""}`);
  }

  /**
   * Runs the injected check (a real prompt through the agent). After a code was typed, a failed check
   * is retried while the CLI is still running without an error, until the sign-in timeout (`final`).
   */
  private async runVerification(fromStartup: boolean, final = false) {
    if (TERMINAL.has(this.state) || this.state === "verifying") return;
    const gen = ++this.verifyGen;
    this.verifyingFromStartup = fromStartup;
    this.setState("verifying");
    let result: { ok: boolean; detail: string };
    try {
      result = await this.verify();
    } catch (err) {
      result = { ok: false, detail: err instanceof Error ? err.message : String(err) };
    }
    if (gen !== this.verifyGen || TERMINAL.has(this.state)) return; // abandoned or cancelled meanwhile
    this.verifyingFromStartup = false;
    if (result.ok) {
      this.alreadySignedIn = fromStartup;
      this.setState("signed_in", fromStartup ? "Already signed in. The agent is ready." : undefined);
      this.close();
    } else if (!fromStartup && !final && this.term && this.now() - this.codeAt < this.t.signInTimeoutMs) {
      // Not answering yet: the CLI may still be saving the sign-in. Keep watching.
      this.lastBusyAt = this.now();
      this.setState("signing_in", "Signing in… waiting for the CLI to finish.");
    } else {
      this.fail(
        fromStartup
          ? `The Antigravity CLI showed no login screen and the agent did not answer: ${result.detail}`
          : `Sign-in did not complete: ${result.detail}`,
      );
    }
  }

  private sendKeys(keys: string[]) {
    keys.forEach((k, i) => {
      const timer = setTimeout(() => {
        try {
          this.term?.write(k);
        } catch {
          /* terminal closed; onExit reports it */
        }
      }, (i + 1) * this.t.keyDelayMs);
      this.keyTimers.push(timer);
    });
  }

  private fail(message: string) {
    this.verifyGen++;
    this.setState("failed", message);
    this.close();
  }

  private setState(state: AgyLoginState, message?: string) {
    const changed = state !== this.state || (message ?? MESSAGES[state]) !== this.message;
    this.state = state;
    this.message = message ?? MESSAGES[state];
    this.touch();
    if (changed && this.onChange) {
      try {
        this.onChange(this.snapshot());
      } catch {
        /* a listener failure must not break the sign-in */
      }
    }
  }

  private touch() {
    this.updatedAt = this.now();
  }

  private armPhaseTimer(ms: number, fn: () => void) {
    if (this.phaseTimer) clearTimeout(this.phaseTimer);
    this.phaseTimer = setTimeout(fn, ms);
    this.phaseTimer.unref?.();
  }

  /** Leaves the CLI and stops the terminal. The CLI saved the sign-in itself. */
  private close() {
    for (const timer of [this.evalTimer, this.phaseTimer, ...this.keyTimers]) {
      if (timer) clearTimeout(timer);
    }
    if (this.signInPoll) clearInterval(this.signInPoll);
    this.evalTimer = this.phaseTimer = this.signInPoll = null;
    this.keyTimers = [];
    const term = this.term;
    if (!term) return;
    this.term = null;
    try {
      term.write(KEY_CTRL_C);
      term.write(KEY_CTRL_C);
    } catch {
      /* already gone */
    }
    const killer = setTimeout(() => term.kill(), 1500);
    killer.unref?.();
  }
}

/** Minimal child-process surface the terminal adapter needs (a `script` PTY wrapper, locally or via docker exec). */
export type PtyChild = {
  stdin: { write(data: string): unknown; on(event: "error", listener: (err: Error) => void): unknown };
  stdout: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown };
  stderr: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown };
  on(event: "exit", listener: (code: number | null) => void): unknown;
  on(event: "error", listener: (err: Error) => void): unknown;
  kill(signal?: NodeJS.Signals): boolean;
};

/**
 * Wraps a process that runs a command under `script` (util-linux), which gives it a real
 * pseudo-terminal: what is written to stdin arrives as key presses. stderr is merged into the
 * output so a failure (e.g. "No such container") shows up in the transcript.
 */
export function ptyChildTerminal(child: PtyChild): LoginTerminal {
  const dataListeners: Array<(chunk: string) => void> = [];
  const exitListeners: Array<(code: number | null) => void> = [];
  let exited = false;
  const emit = (chunk: Buffer | string) => {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    for (const l of dataListeners) l(text);
  };
  const finish = (code: number | null) => {
    if (exited) return;
    exited = true;
    for (const l of exitListeners) l(code);
  };
  child.stdout.on("data", emit);
  child.stderr.on("data", emit);
  child.stdin.on("error", () => {
    /* EPIPE once the process is gone: reported through exit */
  });
  child.on("exit", (code) => finish(code));
  child.on("error", (err) => {
    emit(`\n${err.message}\n`);
    finish(null);
  });
  return {
    write: (data) => {
      if (!exited) child.stdin.write(data);
    },
    onData: (l) => void dataListeners.push(l),
    onExit: (l) => void exitListeners.push(l),
    kill: () => {
      if (!exited) child.kill("SIGKILL");
    },
  };
}
