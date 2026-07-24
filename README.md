# Produit Academy - Centralized Backend

This is the central Django REST Framework backend that powers all of the Produit Academy frontend platforms (Classes, Staff, Main, Careers, GATE).

## Features
- **Authentication**: JWT-based authentication using `djangorestframework_simplejwt`.
- **Database**: PostgreSQL integration for relational data storage.
- **API Endpoints**: RESTful APIs for student dashboards, booking slots, teacher onboarding, payments, and mock tests.
- **Emailing**: Configured with `django-anymail`.

## Tech Stack
- Python 3.x
- Django 5.2
- Django REST Framework 3.16
- PostgreSQL (`psycopg2-binary`)
- Simple JWT

## Getting Started

### Prerequisites
Make sure you have Python installed and PostgreSQL running on your machine.

### Setup Instructions

1. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Variables**:
   Create a `.env` file in the root of the project with your local database credentials and secret keys.

4. **Database Migrations**:
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Run the Development Server**:
   ```bash
   python manage.py runserver
   ```

The API will be available at `http://127.0.0.1:8000/`.

## API Documentation
Check the `urls.py` files within specific apps for detailed endpoint structures. Ensure CORS is configured properly via `django-cors-headers` to accept requests from the various Next.js frontends during local development.
