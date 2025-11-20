# GPF Database - Flask (Railway Ready) - v2

Improvements in v2:
- SQLAlchemy + PostgreSQL support (uses DATABASE_URL env var; fallback to SQLite)
- CSRF protection using Flask-WTF
- WTForms validation for member & user forms
- Edit member feature
- Import/Export CSV & Excel (xlsx) using pandas (openpyxl)
- Improved UI: Google Fonts, Bootstrap icons, spacing to match screenshots
- Ready for Railway + PostgreSQL addon

## Deploy notes
- Set `SECRET_KEY` and (recommended) `DATABASE_URL` in Railway environment variables.
- If `DATABASE_URL` is not set, app will use local SQLite at `instance/gpf.db`.
- `Procfile` uses `gunicorn app:app`.

Default admin created on first startup: username `admin`, password `admin123`. Change it after login.
