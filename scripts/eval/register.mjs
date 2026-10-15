// Loaded with `node --import ./scripts/eval/register.mjs`; installs the resolve hook below.
import { register } from "node:module";

register("./hooks.mjs", import.meta.url);
