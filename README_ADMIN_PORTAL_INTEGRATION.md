# BC Eats Admin Portal — MongoDB-authoritative permissions

## Admin authorization model

MongoDB is the sole authority for application roles. Create or update the intended administrator's existing user document so `email` is normalized to lowercase and `role` is exactly `admin` (case-insensitive checks are supported by authorization middleware). Do not grant admin permissions from the Microsoft token, frontend, environment variables, or a client-provided role.

Microsoft login (`POST /api/users/microsoft-login` or `POST /api/microsoft/login`) verifies the Microsoft token, finds an existing MongoDB user by linked Microsoft object ID or verified email, rejects unknown users, and rejects any user whose database role is not `admin`. It does not auto-create users or elevate roles. Successful login issues the application's own JWT.

Every route using `requireRoles(...)` now fetches the current role from MongoDB for each request. A role downgrade or account deletion therefore takes effect immediately, even if an old app JWT has not expired. Ensure every admin-only endpoint is protected by `identifier` and `requireRoles('admin')` (or a narrower role list where intended).

## Microsoft scopes

If the frontend sends a Microsoft **ID token** to the backend login endpoint and the backend validates its audience against `MICROSOFT_CLIENT_ID`, a custom `access_as_user` scope is not inherently required. Request the sign-in scopes supported by the frontend configuration (commonly `openid`, `profile`, and `email`) and keep the backend token audience aligned with the app registration that issued that ID token.

If instead the frontend sends an **access token for a separately registered backend API**, configure `access_as_user` on that API's app registration and validate the access token against the API's client ID/audience. Do not mix the ID-token and API-access-token flows.

## Required environment variables

- `TOKEN_SECRET`: strong private secret for BC Eats application JWTs.
- `MICROSOFT_CLIENT_ID`: audience/client ID for the Microsoft token this backend validates.
- `MICROSOFT_AUTHORITY=https://login.microsoftonline.com/common`
- MongoDB connection setting used by this project (`MONGO_URI` or the existing configured variable).

## Deploying

Deploy the updated backend and set its environment variables in the hosting provider. Never put `TOKEN_SECRET` in Flutter or expose it to the browser. Test with one database user whose role is `admin`, then test a normal customer account and confirm it receives HTTP 403 from admin endpoints.
