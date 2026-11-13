// For tests against a local relay only. A client made here may use ws:// to 127.0.0.1 or [::1];
// the core still refuses every other plaintext relay. Production code imports the package root.
import { ClientOptions, LOOPBACK, TetherClient } from "./client.js";

export function createTestClient(options: ClientOptions): Promise<TetherClient> {
  return TetherClient.create({ ...options, [LOOPBACK]: true } as ClientOptions);
}
