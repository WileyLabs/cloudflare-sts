// Copyright (c) 2026 John Wiley & Sons, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

export class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export function ensure(cond, status, code) {
  if (!cond) throw new HttpError(status, code);
}
