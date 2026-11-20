export class AbeError extends Error {
  constructor(code, operation, detail) {
    super(`${operation}: ${detail} (code: ${code})`);
    this.name = new.target.name;
    this.code = code;
    this.operation = operation;
  }
}
export class PolicyMismatchError extends AbeError {}
export class SignatureInvalidError extends AbeError {}

