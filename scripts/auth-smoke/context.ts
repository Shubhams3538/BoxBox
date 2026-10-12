import { type Fixture } from "./fixtures";
import { type Result } from "./types";
import { type Subprocess } from "bun";

export type SmokeContext = Fixture & {
  binaryPath: string;
  backendDir: string;
  processes: Subprocess[];
  issuedTokens: string[];
  results: Result[];
};
