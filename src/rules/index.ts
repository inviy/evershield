import { internalEndpoint } from "./internal-endpoint.ts";
import { secretLikeString } from "./secret-like-string.ts";
import { sensitiveFileShipped } from "./sensitive-file-shipped.ts";
import { sensitiveEnvName } from "./sensitive-env-name.ts";
import { sourceMapPublished } from "./source-map-published.ts";
import type { Rule } from "./types.ts";

/** Layer 1 rules, in report order. */
export const ARTIFACT_RULES: readonly Rule[] = [
  secretLikeString,
  sourceMapPublished,
  sensitiveFileShipped,
  sensitiveEnvName,
  internalEndpoint,
];

export type { Rule, RuleContext } from "./types.ts";
