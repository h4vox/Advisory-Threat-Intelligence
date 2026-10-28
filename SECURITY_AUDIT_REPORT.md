# Security Audit & Hardening Report

**Target Application:** Advisory-Threat-Intelligence (`/home/havox/dev/Advisory-Threat-Intelligence`)  
**Assessment Objective:** Identify and document critical security vulnerabilities to safeguard the application against public-facing threats.

---

## Executive Summary

A comprehensive source code security assessment was performed across the authentication subsystem, database persistence layer, API middleware, and container orchestration components.

While the application employs robust modern controls in several areas (e.g., `scrypt` password hashing with timing attack mitigations, strict SSRF validation with DNS rebinding defenses, and parameterization of SQL queries), several **critical and high-severity findings** require remediation prior to public exposure.

---

## Summary of Findings

| Severity | Issue | Primary Location | Remediated Status |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Hardcoded Database Credentials | `src/lib/mongodb/client.server.ts` | Action Required |
| **CRITICAL** | Hardcoded OAuth Client Secret | `src/lib/auth/preview.ts` | Action Required |
| **HIGH** | Unparameterized Shell Execution | `src/lib/aie/server.ts` | Action Required |
| **HIGH** | Missing Role-Based Access Control on Administrative Actions | `src/lib/aie/server.ts`, `src/lib/aie/access.ts` | Action Required |
| **HIGH** | Unbounded Server-Side RegEx (ReDoS Risk) | `src/lib/mongodb/repository.server.ts` | Action Required |
| **MEDIUM** | Incomplete CSRF Protection on Session Ingestion | `src/lib/auth/isolation.server.ts` | Action Required |
| **MEDIUM** | Token Storage in Client Storage | `src/lib/auth/client.ts` | Action Required |
| **LOW** | Network Interface Exposure (`0.0.0.0`) | Dev Server Configuration | Action Required |

---

## Detailed Vulnerability Analysis & Remediation

### 1. Hardcoded MongoDB Production Credentials (CRITICAL)

- **File:** `src/lib/mongodb/client.server.ts` (Lines 33–34)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

#### Observation
The application source code defines a fallback connection string pointing directly to an external MongoDB Atlas cluster:
```typescript
const DEFAULT_MONGODB_URI =
  "mongodb+srv://threatintel_app:[REDACTED]@cluster0.gr9ihel.mongodb.net/?appName=Cluster0";
```

#### Risk & Attack Surface
If repository source code, build artifacts, or client bundles are accessible to external parties, adversaries obtain full administrative read/write access to the application database, bypassing application-level access controls.

#### Remediation Plan
1. **Rotate Credentials:** Immediately rotate the password for user `threatintel_app` inside the MongoDB Atlas console.
2. **Fail Closed:** Remove fallback values. The server must refuse to start if `MONGODB_URI` is unset.
```typescript
// Recommended Fix in src/lib/mongodb/client.server.ts
function getMongoUri(): string {
  const uri = process.env.MONGODB_URI?.trim();
  if (!uri) {
    throw new Error("FATAL: MONGODB_URI environment variable is required.");
  }
  return uri;
}
```

---

### 2. Hardcoded OAuth Client Secret (CRITICAL)

- **File:** `src/lib/auth/preview.ts` (Lines 20–21)
- **CWE:** [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

#### Observation
The preview OAuth integration embeds a static client secret directly within source code:
```typescript
export const PREVIEW_CLIENT_SECRET = "[REDACTED_SECRET]";
```

#### Risk & Attack Surface
Attackers possessing this key can forge authentication requests and impersonate legitimate clients during broker exchanges.

#### Remediation Plan
Extract all OAuth secrets to runtime configuration (`process.env.PREVIEW_CLIENT_SECRET`) and rotate the currently exposed secret across your auth providers.

---

### 3. Command Injection Risk via Unparameterized Shell Invocation (HIGH)

- **File:** `src/lib/aie/server.ts` (Lines 2948, 2958, 2986, 2996, 3441, 3554)
- **CWE:** [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)

#### Observation
Several administrative routines construct shell commands using template literal string concatenation:
```typescript
// Vulnerable Pattern:
execSync(`docker exec ${sandboxInfo.containerName} which claude`, ...);
execSync(`docker exec ${sandboxInfo.containerName} npm install -g @anthropic-ai/claude-code@${existing.version || "latest"}`, ...);
```

#### Risk & Attack Surface
`execSync` invokes an underlying shell (`/bin/sh` on POSIX systems). If any interpolated variable (such as package version numbers or container tags supplied via administrative API calls or database entries) contains shell metacharacters (e.g., semicolons, backticks, pipes), arbitrary commands may execute with the permissions of the Node.js server process.

#### Remediation Plan
Migrate from shell-invoked `execSync` to direct argument array invocation via `execFileSync` or `execFile`. This bypasses shell interpolation entirely:

```typescript
// Recommended Fix:
import { execFileSync } from "node:child_process";

// Execute without an intermediate shell
execFileSync("docker", [
  "exec",
  sandboxInfo.containerName,
  "npm",
  "install",
  "-g",
  `@anthropic-ai/claude-code@${sanitizedVersion}`
], { encoding: "utf-8", timeout: 30000 });
```

---

### 4. Insufficient Role Separation on Privileged Operations (HIGH)

- **File:** `src/lib/aie/server.ts`, `src/lib/aie/access.ts`
- **CWE:** [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

#### Observation
Administrative server functions (such as package installations inside containers, feed modifications, and diagnostics) rely on `analystMiddleware`. The application context extracts `identity.role`, but individual server functions do not enforce that `role === 'admin'`.

#### Risk & Attack Surface
An attacker who compromises or registers a low-privileged user account (e.g., an analyst role) can invoke backend maintenance and container management APIs that should be restricted strictly to system administrators.

#### Remediation Plan
Implement a dedicated role-validation middleware:
```typescript
// src/lib/auth/admin-middleware.ts
export const adminMiddleware = createMiddleware().middleware([analystMiddleware]).server(async ({ next, context }) => {
  if (context.identity.role !== "admin") {
    throw new Error("Access Denied: Requires Administrator Privileges.");
  }
  return next();
});
```
Apply `adminMiddleware` to all agent installation, system diagnostics, and account management routes.

---

### 5. Server-Side ReDoS on Document Search (HIGH)

- **File:** `src/lib/mongodb/repository.server.ts` (Lines 683–704)
- **CWE:** [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)

#### Observation
User queries are transformed into regular expressions and executed directly across large document text fields (`extractedText`) without explicit database timeout ceilings.

#### Risk & Attack Surface
An external attacker can submit crafted queries with high backtracking complexity, locking MongoDB worker threads and consuming 100% database CPU, resulting in a denial of service (DoS) for all application users.

#### Remediation Plan
1. **Set Query Timeouts:** Enforce `.maxTimeMS(2000)` on all `$regex` queries.
2. **Prioritize Full-Text Search:** Restrict regular expressions to short indexed metadata fields (title, publisher, ID); route large content searches exclusively to MongoDB `$text` search indexes.

---

### 6. Public Exposure & Network Boundary Hardening (MEDIUM)

- **Configuration:** Vite Dev Server listening on `0.0.0.0:8080`

#### Observation
The application is currently bound to all network interfaces (`0.0.0.0:8080`) using the Vite development server.

#### Risk & Attack Surface
Running development servers on public-facing interfaces exposes development-only endpoints, HMR (Hot Module Replacement) WebSocket listeners, and verbose error stacks to the Internet.

#### Remediation Plan
1. **Production Build:** Build the optimized client bundle (`npm run build`) and serve using a production process manager or container.
2. **Reverse Proxy:** Terminate TLS and route incoming web traffic through Nginx or Cloudflare, binding the internal application server strictly to `127.0.0.1`.
3. **Security Headers:** Enforce HTTP security headers:
   - `Content-Security-Policy: default-src 'self';`
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Strict-Transport-Security: max-age=63072000; includeSubDomains`

---

## Action Checklist for the Development Team

- [ ] **Step 1:** Rotate MongoDB Atlas password and update production secrets.
- [ ] **Step 2:** Remove fallback connection strings and credentials from source code.
- [ ] **Step 3:** Refactor all `execSync` template calls in `src/lib/aie/server.ts` to `execFileSync` with argument arrays.
- [ ] **Step 4:** Enforce `adminMiddleware` on all agent/container lifecycle server actions.
- [ ] **Step 5:** Attach `.maxTimeMS(2000)` to MongoDB search operations.
- [ ] **Step 6:** Place the application behind a reverse proxy with TLS termination and bind the Node process to localhost.
