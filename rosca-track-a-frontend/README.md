## Requirements

- Node.js 18 or newer
- The D4 `rosca-api` backend running separately

## Secure sign in

The dashboard authenticates through the API with an HttpOnly session cookie.
On first run use the first-time setup link to create the initial organizer account
(password minimum 12 characters). Bootstrap is disabled once the first account
exists. Member accounts are provisioned by an organizer and see only their own
scoped `/api/me` information.
