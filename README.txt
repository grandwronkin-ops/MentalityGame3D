MENTALITYGAME 3D ONLINE — ANDROID-FRIENDLY SERVER PROJECT

WHAT IS INCLUDED
- Browser 3D city prototype
- Account registration and login
- Live player position sync and global chat using Socket.IO
- Founder L7 account seeded from server environment variables
- Founder-only promotion/demotion of Admin L1-L6
- Admin panel hidden from regular players
- Server-side authorization for staff endpoints
- L3+ can ban lower-ranked accounts

IMPORTANT LIMITATION
This ZIP is a server project, not a one-tap hosted game. Multiplayer works only after this Node.js server is deployed online.
Opening public/index.html as a local file will NOT provide multiplayer or Founder/Admin services.
The 3D engine is loaded from a CDN, so players need internet access.
The included protections are a prototype baseline, not a professional security audit or production certification.

DEPLOYMENT REQUIREMENTS
- Node.js 20+
- Persistent writable disk/storage for data.json
- Set PORT (usually provided by host)
- Set SESSION_SECRET to a random string of 32+ characters
- Set FOUNDER_USERNAME
- Set FOUNDER_PASSWORD to a unique password of 12+ characters
- Install dependencies with npm install
- Start with npm start
- Use HTTPS on the public deployment URL

ANDROID NOTE
You can manage/download/extract this project on Android. A public multiplayer URL still requires a cloud host to run the server continuously. This ZIP does not create a cloud account, deploy itself, or include a live URL.

ROLE RULES
- Player = role 0
- Admin = role 1 through 6
- Founder = role 7
- Only Founder can assign or remove Admin roles.
- Admin ranks cannot modify Founder or accounts at their own/higher rank.
- Staff panel is not shown to role 0 players; server checks permissions independently.

This is an early multiplayer prototype. Before public launch, add automated tests, audit logs, stronger movement validation, persistent database backups, abuse controls, and an independent security review.
