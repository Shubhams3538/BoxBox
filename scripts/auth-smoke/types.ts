export type TokenPair = { accessToken: string; refreshToken: string };

export type Result = {
  scenario: string;
  outcome: "PASS" | "LIMITATION (expected risk)" | "FAIL";
  evidence: string;
};

export type CredentialTransport = "header" | "query";
