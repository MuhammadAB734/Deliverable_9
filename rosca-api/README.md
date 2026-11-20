## Run

1. Install Node.js 18+.
2. From this folder:

```bash
npm install
npm start
```

The API runs on `http://localhost:3000`.

## Main endpoints

### Members
- GET `/api/members`
- GET `/api/members/:id`
- POST `/api/members`
- PUT `/api/members/:id`
- DELETE `/api/members/:id`

### Circles
- GET `/api/circles`
- GET `/api/circles/:id`
- POST `/api/circles`
- PUT `/api/circles/:id`
- DELETE `/api/circles/:id`
- POST `/api/circles/:id/generate-schedule`

### Memberships
- GET/POST `/api/memberships`
- GET/PUT/DELETE `/api/memberships/:id`

### Cycles
- GET/POST `/api/cycles`
- GET/PUT/DELETE `/api/cycles/:id`

### Contributions
- GET/POST `/api/contributions`
- GET/PUT/DELETE `/api/contributions/:id`

### Payouts
- GET/POST `/api/payouts`
- GET/PUT/DELETE `/api/payouts/:id`

### Utility
- GET `/api/health`
- GET `/api/docs`
## Authentication and role-based access

The API creates `app_users` and `app_sessions` automatically after connecting to
the existing database. The equivalent migration is `migrations/001_authentication.sql`.

- First-time setup: `POST /api/auth/bootstrap` with `{ "username": "...", "password": "..." }`.
  The password must be at least 12 characters. Bootstrap is disabled after the first account.
- Login: `POST /api/auth/login`; logout: `POST /api/auth/logout`; current user:
  `GET /api/auth/me`.
- The API uses Node.js scrypt password hashes and random opaque session tokens.
  Only a SHA-256 token hash is stored in MySQL. The browser cookie is HttpOnly,
  SameSite=Strict, and Secure when `NODE_ENV=production`.
- Organizer provisions member accounts through `POST /api/auth/users` with
  `{ "username": "...", "password": "...", "role": "MEMBER", "member_id": 1 }`.
- All management CRUD and schedule-generation routes require ORGANIZER. Members
  can access only their own profile, memberships, contributions and payouts via
  `GET /api/me`. Authorization derives from the server session, not request fields.
- Set `CORS_ORIGIN` to the exact frontend origin. Use HTTPS and a least-privilege
  MySQL account in production.
