/**
 * Command-line flags for prompts sent to the Antigravity CLI (`agy`) in stream-json mode.
 *
 * `--print` takes the prompt as its value, so a bare `--print` swallows the next flag (the real CLI:
 * `--print took "--disable-slash-commands" as its prompt … Attach the prompt to the flag`). The
 * prompt travels over stdin as stream-json, so the value is attached and empty (`--print=`) and kept
 * last. A CLI that refuses that runs headless without it (the documented
 * `agy --input-format stream-json --output-format stream-json` form); a CLI without
 * `--disable-slash-commands` runs without that flag. The form is learnt from the CLI's own usage
 * errors (exit code 2).
 *
 * Pure module: no imports, unit-tested against a test double of the CLI.
 */

export type AgyCliFlavor = { print: "attached" | "omit"; slashCommandsFlag: boolean };

export const DEFAULT_AGY_CLI_FLAVOR: AgyCliFlavor = { print: "attached", slashCommandsFlag: true };

/** Flags for one stream-json run. `extra` (e.g. `--conversation <id>`) goes before the print flag. */
export function agyStreamJsonArgs(flavor: AgyCliFlavor, model: string, extra: string[] = []): string[] {
  const args = [
    ...(flavor.slashCommandsFlag ? ["--disable-slash-commands"] : []),
    "--input-format",
    "stream-json",
    "--output-format",
    "stream-json",
    "--model",
    model,
    ...extra,
  ];
  if (flavor.print === "attached") args.push("--print=");
  return args;
}

/**
 * The flag form to use after a usage error, or null when the error is not about these flags.
 * Each step is taken once, so a CLI that keeps failing does not loop.
 */
export function nextAgyCliFlavor(flavor: AgyCliFlavor, errorText: string): AgyCliFlavor | null {
  const text = errorText || "";
  if (flavor.print === "attached" && /--print\b|(?:^|\s)-p\b|\bprint mode\b/i.test(text) && /prompt|argument|value|flag|empty|unknown|invalid/i.test(text)) {
    return { ...flavor, print: "omit" };
  }
  if (flavor.slashCommandsFlag && /disable-slash-commands/i.test(text) && /unknown|not recogni[sz]ed|invalid|unsupported|undefined/i.test(text)) {
    return { ...flavor, slashCommandsFlag: false };
  }
  return null;
}
