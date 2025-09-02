# Lost & Found (Flask + MySQL)

A simple lost & found website: users sign up/login, post lost items, report found items with photos, and an admin can delete misuse posts.

## 1) Prerequisites
- Python 3.10+
- MySQL Server (local or hosted)
- (Optional) Git
- (Optional) Railway or Render account for deployment

## 2) Setup (Local)

```bash
# 2.1. Create and activate a virtual environment
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2.2. Install dependencies
pip install -r requirements.txt

# 2.3. Create database & tables
# Log into MySQL and run schema.sql
# Example:
#   mysql -u root -p < schema.sql

# 2.4. Configure environment
cp .env.example .env
# Edit .env with your MySQL credentials and a random SECRET_KEY

# 2.5. Run the app
python app.py
# Visit http://localhost:5000
```

### Make yourself admin
1. Sign up via the web UI.
2. In MySQL shell, run:
```sql
UPDATE users SET role='admin' WHERE email='your@email.com';
```

## 3) Deploy (Railway - app + MySQL)

Railway can host both your Python app and a managed MySQL instance.

1. Push this project to a GitHub repo.
2. Create a new **Railway** project and add the **MySQL** plugin (provision a database).
3. Note the DB credentials (host, port, user, password, database).
4. Create a new **Service** from your GitHub repo (Python).
5. Set **Environment Variables** in Railway Service:
   - `SECRET_KEY` = a long random string
   - `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` = from the MySQL plugin
6. **Build & Start Command** (Railway usually detects):
   - Start Command: `gunicorn app:app`
7. Open the deployed URL.
8. Sign up with your admin email, then run the SQL to make yourself admin.

## 4) Deploy (Render - app) + External MySQL
Render doesn't provide MySQL directly. Use an external MySQL (Railway, Aiven, PlanetScale, etc.).
- On Render, create a **Web Service** from your GitHub repo.
- Under **Environment**, add variables as above.
- **Start Command**: `gunicorn app:app`

## 5) Notes
- Images are stored on-disk at `static/uploads/`. On multi-instance deployments, switch to cloud storage (e.g., S3) later.
- For simplicity, no CSRF protection or email verification is included. Add these before production use.
- You can add more fields (phone number, item categories, map locations) as needed.
