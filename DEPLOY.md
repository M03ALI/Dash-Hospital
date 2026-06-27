# Deploying to Streamlit Community Cloud

## Files you need in your repo
```
hospital_dashboard.py      ← the app (this is what Streamlit runs)
requirements.txt           ← dependencies
.streamlit/config.toml     ← light theme
.streamlit/secrets.toml    ← analyst credential (DO NOT commit real values)
make_hash.py               ← helper to create a password hash (optional)
.gitignore                 ← keeps secrets/db out of git
```
You do NOT need `hospitalapp_builder.py` to deploy — that builder is only for
generating a single-file copy locally. Streamlit runs `hospital_dashboard.py` directly.

## Steps
1. Push these files to a GitHub repo (the `.gitignore` keeps `secrets.toml` and `*.db` out).
2. Go to https://share.streamlit.io → **New app**, pick your repo/branch.
3. Set **Main file path** to `hospital_dashboard.py`.
4. Open **Advanced settings → Secrets** (or App → Settings → Secrets after creating) and paste:
   ```toml
   HOSPITAL_ADMIN_PASSWORD_HASH = "pbkdf2_sha256$600000$....$...."
   ```
   Generate that value first with:
   ```bash
   python make_hash.py "your-strong-password"
   ```
   (Or use the simpler `HOSPITAL_ADMIN_PASSWORD = "your-strong-password"` instead.)
5. Click **Deploy**.

### Optional: two-factor authentication (2FA)
For an extra layer on the analyst login, add a TOTP secret to **Secrets**:
```toml
HOSPITAL_ADMIN_TOTP_SECRET = "BASE32SECRET..."
```
Generate one from **Data Entry → ⚙️ Settings → Generate 2FA secret**, add the printed
key (or `otpauth://` link) to an authenticator app (Google Authenticator, Authy, 1Password),
then restart. When set, the login asks for a 6-digit code in addition to the password.
No extra packages are required — 2FA uses only the Python standard library.

## Notes
- Light/dark display is a per-viewer toggle in the sidebar ("🌙 Dark mode"); the default is light.
- If you skip the secret, the analyst password falls back to `changeme` and a warning shows.
  Set a real secret before sharing the link.
- The SQLite database lives on the app's container. On Community Cloud this storage is
  **ephemeral** — it can reset when the app restarts/redeploys. For permanent storage, point
  `HOSPITAL_DB_PATH` at a mounted volume, or move to a hosted database (e.g. Postgres) — I can
  help wire that up if needed.
- To run locally instead:
  ```bash
  pip install -r requirements.txt
  streamlit run hospital_dashboard.py
  ```
