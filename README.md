# Produit Academy Backend

This is the backend API for Produit Academy, built with Django and Django REST Framework.

## Tech Stack

- **Framework**: Django
- **API**: Django REST Framework
- **Server**: Gunicorn (Production), Django Dev Server (Local)
- **Database**: SQLite (Local), Postgres (Production recommended)

## Getting Started

### Prerequisites

- Python 3.9+
- pip
- virtualenv (recommended)

### Installation

1. Navigate to the backend directory:
   ```bash
   cd produit_academy_backend
   ```
2. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
3. Activate the virtual environment:
   - **Windows**: `venv\Scripts\activate`
   - **macOS/Linux**: `source venv/bin/activate`
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Database Setup

Run migrations to set up the database schema:

```bash
python manage.py migrate
```

### Running Locally

Start the development server:

```bash
python manage.py runserver
```

The API will be available at `http://localhost:8000`.

## Deployment

The project includes specific files for deployment (e.g., on Render, Heroku):

- `build.sh`: Script to install dependencies, collect static files, and run migrations.
- `Procfile`: Command to run the application using Gunicorn.

### Build Script
```bash
./build.sh
```

### Production Server
```bash
gunicorn produit_academy_backend.wsgi
```

## Project Structure

- `produit_academy_backend/`: Project settings and WSGI/ASGI config.
- `api/`: Main application logic (models, views, serializers).
- `media/`: User-uploaded content.
- `manage.py`: Django command-line utility.
