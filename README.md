# Lost & Found (Flask + MySQL)

A simple Lost & Found web application built using Flask and MySQL.  
Users can sign up, log in, post lost items, report found items (with photos), and an admin can manage or delete misuse posts.

***

## Features
- User registration and login authentication  
- Post lost and found items with descriptions and photos  
- Admin panel to manage or delete inappropriate posts  
- Image upload support (stored locally in `static/uploads/`)  
- Simple and clean UI with Flask templates  

***

## Tech Stack
- **Backend:** Flask (Python)  
- **Database:** MySQL  
- **Frontend:** HTML, CSS, Bootstrap  
- **Deployment:** Railway / Render (optional)  

***

## Prerequisites
- Python 3.10 or newer  
- MySQL Server (local or hosted)  
- (Optional) Git  
- (Optional) Railway or Render account for deployment  

***

## Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/lost-found.git
cd lost-found

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create the database and tables
# Log into MySQL and run:
# mysql -u root -p < schema.sql

# 5. Configure environment variables
cp .env.example .env
# Edit .env with your MySQL credentials and a random SECRET_KEY

# 6. Run the app
python app.py
# Visit http://localhost:5000
```

***

## Make Yourself Admin
1. Sign up via the web interface.  
2. In MySQL shell, run:
```sql
UPDATE users SET role='admin' WHERE email='your@email.com';
```

***

## Deployment

### Option 1: Railway (App + MySQL)
1. Push your project to GitHub.  
2. On **Railway**, create a new project and add the **MySQL** plugin.  
3. Note your MySQL credentials (host, port, user, password, database).  
4. Add your Flask app as a **Service** (connect GitHub repo).  
5. Set environment variables:
   - SECRET_KEY = your-secret-key  
   - DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (from Railway MySQL)  
6. Start Command:
   ```
   gunicorn app:app
   ```
7. Open the deployed URL and create your admin account.

***

### Option 2: Render (App) + External MySQL
1. Provision an external MySQL instance (e.g., Railway, PlanetScale, Aiven).  
2. On **Render**, create a new Web Service using your GitHub repo.  
3. Add the same environment variables as above.  
4. Start Command:
   ```
   gunicorn app:app
   ```
5. Access the public URL and configure admin rights.

***

## Folder Structure
```
lost-found/
├── app.py
├── schema.sql
├── requirements.txt
├── .env.example
├── static/
│   └── uploads/
├── templates/
│   ├── login.html
│   ├── register.html
│   ├── lost_items.html
│   └── found_items.html
└── README.md
```

***

## Notes
- Uploaded images are stored locally in `static/uploads/`. For multi-instance deployments, consider using cloud storage (S3, Cloudinary, etc.).  
- CSRF protection and email verification are **not** implemented for simplicity. Add them for production use.  
- You can extend the schema to include:
  - Contact details  
  - Item categories  
  - Map location support  

