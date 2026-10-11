export function expect(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function expectStatus(
  response: Response,
  expected: number,
  label: string,
): void {
  if (response.status !== expected) {
    throw new Error(
      `${label}: expected HTTP ${expected}, received HTTP ${response.status}`,
    );
  }
}
