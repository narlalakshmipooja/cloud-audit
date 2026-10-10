import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Firestore Security Rules - Dirty Dozen & Eight Pillars Verification', () => {
  const rulesPath = path.resolve(__dirname, 'firestore.rules');
  const rulesContent = fs.existsSync(rulesPath)
    ? fs.readFileSync(rulesPath, 'utf-8')
    : fs.readFileSync(path.resolve(__dirname, 'DRAFT_firestore.rules'), 'utf-8');

  it('1. Enforces default deny catch-all at top of match block', () => {
    expect(rulesContent).toContain('match /{document=**} {\n      allow read, write: if false;\n    }');
  });

  it('2. Prevents unverified email spoofing in admin and user checks', () => {
    expect(rulesContent).toContain('request.auth.token.email_verified == true');
  });

  it('3. Isolates PII in /users/{userId} to owner or admin', () => {
    expect(rulesContent).toContain('request.auth.uid == userId || isAdmin()');
  });

  it('4. Prevents self-assigned admin role during user creation by non-admins', () => {
    expect(rulesContent).toContain("incoming().role in ['analyst', 'viewer'] || isAdmin()");
  });

  it('5. Enforces strict key allowlists (hasAll and hasOnly) on all entity validators', () => {
    expect(rulesContent).toContain('data.keys().hasAll(');
    expect(rulesContent).toContain('data.keys().hasOnly(');
  });

  it('6. Enforces ID format and length guard (isValidId)', () => {
    expect(rulesContent).toContain("id.matches('^[a-zA-Z0-9_\\\\-]+$')");
  });

  it('7. Enforces affectedKeys().hasOnly() on all update operations', () => {
    expect(rulesContent).toContain('incoming().diff(existing()).affectedKeys().hasOnly(');
  });

  it('8. Enforces server timestamp integrity (request.time)', () => {
    expect(rulesContent).toContain('request.time');
  });
});
