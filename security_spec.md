# Security Specification (`security_spec.md`)

## 1. Data Invariants
1. **Authentication & Verification Gate**: Every read or write operation requires an authenticated user (`request.auth != null`) with a verified email (`request.auth.token.email_verified == true`).
2. **PII Isolation (`users/{userId}`)**: User documents contain PII (`email`, `displayName`). Read (`get`, `list`) access on `/users/{userId}` is strictly restricted to the document owner (`request.auth.uid == userId`) or a verified administrator (`isAdmin()`).
3. **Self-Assigned Role Prevention**: When creating their own profile in `/users/{userId}`, non-admin users cannot assign themselves the `"admin"` role (`incoming().role in ['analyst', 'viewer']`), whereas the bootstrapped admin email (`2400560511bba@gmail.com`) or existing admins can hold `"admin"`. During updates, users cannot escalate their own `role` unless `isAdmin()`.
4. **Strict Admin Enforcement on Mutating Security Configs**: Creating, updating, or deleting `retention_policies`, `retention_executions`, `integration_settings`, or `audit_logs` requires `isAdmin()`.
5. **Strict Schema & Key Validation**: Every `create` and `update` operation validates exact allowed keys (`hasOnly`), required keys (`hasAll`), string length bounds (`.size() <= MAX`), enum values, and immutable fields (`id`, `createdAt`, `uid`).
6. **Temporal Integrity**: Creation and update timestamps (`createdAt`, `updatedAt`, `executedAt`, `lastLoginAt`) must equal `request.time`.

## 2. The "Dirty Dozen" Payloads
1. **Unverified Admin Email Spoof**: Authenticated token with `email: "2400560511bba@gmail.com"` and `email_verified: false` attempting to delete a retention policy.
2. **Self-Role Escalation on Create**: Standard user `uid: "user_123"` creating `/users/user_123` with `role: "admin"`.
3. **Self-Role Escalation on Update**: Standard user `uid: "user_123"` updating `/users/user_123` with `role: "admin"`.
4. **PII Horizontal Scrape**: Standard user `uid: "user_123"` reading `/users/user_999`.
5. **Shadow Field Injection on Retention Policy**: Admin creating `/retention_policies/pol_1` with an extra undeclared field `"bypassCleanup": true`.
6. **ID Poisoning Attack**: Attempting to create a document with a 500-character ID or special characters `pol_1$%^&*`.
7. **Value Poisoning on Retention Days**: Admin updating `/retention_policies/pol_1` with `retentionDays: -30` or `retentionDays: "ninety"`.
8. **Immutable Field Tampering**: Admin or user updating `createdAt` or `id` on an existing `retention_policies` or `security_alerts` document.
9. **Unauthorized Audit Log Deletion**: Non-admin user (`role: "viewer"`) attempting to delete `/audit_logs/log_101`.
10. **Client Timestamp Forgery**: Creating `/security_alerts/alert_1` with a past or future `createdAt` timestamp instead of `request.time`.
11. **Oversized String Denial-of-Wallet**: Creating an `audit_logs` document with a 100KB `statusMessage` string (`size() > 512`).
12. **Unbounded Update on Security Alert**: Analyst updating `/security_alerts/alert_1` and modifying `ruleId` or `associatedLogId` instead of allowed review fields (`status`, `reviewedBy`, `reviewedAt`, `updatedAt`).

## 3. Conflict & Red Team Verification Summary
- **Shadow Update Test**: Passed — `hasOnly()` enforced on all entity helpers and `affectedKeys().hasOnly()` enforced on all `update` branches.
- **Email Spoofing Test**: Passed — `request.auth.token.email_verified == true` enforced in `isVerifiedUser()` and `isAdmin()`.
- **PII Blanket Test**: Passed — `/users/{userId}` restricts `get` and `list` to `request.auth.uid == userId || isAdmin()`.
- **Query Trust Test**: Passed — `list` rules on collections enforce `resource.data` checks (`resource.data.source in ['GCP_LIVE', 'DEMO']` or `resource.data.uid == request.auth.uid`).
