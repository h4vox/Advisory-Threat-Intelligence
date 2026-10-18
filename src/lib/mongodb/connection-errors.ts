/**
 * Plain-language causes and fixes for MongoDB connection errors, for the data-source notice.
 * Pure; safe to import from components.
 */

/** Plain-language cause and fix for a MongoDB connection error message. */
export function explainMongoError(message: string): string {
  if (/querySrv|queryTxt|ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(message)) {
    return "The cluster's address could not be looked up. Check the host in MONGODB_URI; AIE already retried through public DNS.";
  }
  if (/bad auth|authentication failed|auth failed|not authorized/i.test(message)) {
    return "MongoDB rejected the username or password in MONGODB_URI. Special characters in the password must be URL-encoded (for example @ as %40).";
  }
  if (/certificate|self[- ]signed|SSL|TLS/i.test(message)) {
    return "The TLS certificate check failed. If antivirus or a proxy inspects encrypted traffic, add its root certificate with NODE_EXTRA_CA_CERTS.";
  }
  if (/timed out|timeout|ETIMEDOUT|ECONNREFUSED|ECONNRESET|server selection|ReplicaSetNoPrimary|connection .* closed/i.test(message)) {
    return "MongoDB did not answer. In MongoDB Atlas, allow this server's IP address under Network Access, and check the server can reach port 27017.";
  }
  return "Check MONGODB_URI in the server environment and restart.";
}
