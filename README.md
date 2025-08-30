# Domain Upgrade Pro SaaS - Installation Guide

This guide provides step-by-step instructions for installing and running the Domain Upgrade Pro SaaS application outside of Replit.

## Overview

Domain Upgrade Pro SaaS is a Flask web application that analyzes domain names to identify potential buyers by finding businesses that rank on Google with similar keywords. The application features user management, payment processing, API credit management, and automated domain analysis.

## Prerequisites

Before installing the application, ensure you have the following installed on your system:

- **Python 3.11 or higher**
- **PostgreSQL 12 or higher**
- **Git** (for cloning the repository)
- **UV package manager** (recommended) or **pip**

## Step 1: System Dependencies

### On Ubuntu/Debian:
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip postgresql postgresql-contrib git
```

### On macOS:
```bash
# Install Homebrew if you haven't already
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.11 postgresql git
```

### On Windows:
- Download Python 3.11 from [python.org](https://www.python.org/downloads/)
- Download PostgreSQL from [postgresql.org](https://www.postgresql.org/download/windows/)
- Install Git from [git-scm.com](https://git-scm.com/download/win)

## Step 2: Clone the Repository

```bash
git clone <your-repository-url>
cd domain-upgrade-pro-saas
```

## Step 3: Install UV Package Manager (Recommended)

UV is a fast Python package manager. Install it using:

```bash
# On macOS/Linux:
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows (PowerShell):
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Alternatively, you can use pip:
```bash
pip install uv
```

## Step 4: Set Up Python Environment

### Using UV (Recommended):
```bash
# Create virtual environment and install dependencies
uv sync
```

### Using pip:
```bash
# Create virtual environment
python3.11 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r pyproject.toml
```

## Step 5: Database Setup

### Start PostgreSQL Service

**On Ubuntu/Debian:**
```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

**On macOS:**
```bash
brew services start postgresql
```

**On Windows:**
Start PostgreSQL service from Services panel or pgAdmin.

### Create Database

```bash
# Switch to postgres user (Linux/macOS)
sudo -u postgres psql

# Or connect directly
psql -U postgres

# In PostgreSQL shell, create database and user:
CREATE DATABASE domain_upgrade_pro;
CREATE USER app_user WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE domain_upgrade_pro TO app_user;
\q
```

## Step 6: Environment Configuration

Create a `.env` file in the project root directory:

```bash
cp .env.example .env  # If .env.example exists
# Or create .env manually
```

Add the following environment variables to your `.env` file:

```env
# Flask Configuration
SECRET_KEY=your-very-secure-secret-key-here-change-this-in-production
FLASK_ENV=development
FLASK_APP=app.py

# Database Configuration
DATABASE_URL=postgresql://app_user:secure_password_here@localhost:5432/domain_upgrade_pro

# API Keys (Required for functionality)
SERPER_API_KEY=your-serper-api-key-here

# Payment Processing (Optional - for production)
STRIPE_PUBLIC_KEY=your-stripe-public-key
STRIPE_SECRET_KEY=your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=your-stripe-webhook-secret

PAYPAL_CLIENT_ID=your-paypal-client-id
PAYPAL_CLIENT_SECRET=your-paypal-client-secret
PAYPAL_MODE=sandbox  # or 'live' for production

# Email Configuration (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Required API Keys

1. **Serper API Key** (Required):
   - Sign up at [serper.dev](https://serper.dev)
   - Get your API key from the dashboard
   - Add it to the `SERPER_API_KEY` environment variable

2. **Stripe Keys** (Optional - for payments):
   - Create account at [stripe.com](https://stripe.com)
   - Get your publishable and secret keys from the dashboard

3. **PayPal Credentials** (Optional - for payments):
   - Create developer account at [developer.paypal.com](https://developer.paypal.com)
   - Create an application and get client ID/secret

## Step 7: Initialize Database

Run database migrations to create all necessary tables:

```bash
# Activate virtual environment if using pip
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows

# Initialize and migrate database
python -c "from app_flask import create_app; from models import db; app = create_app(); app.app_context().push(); db.create_all()"
```

## Step 8: Create Admin User (Optional)

To create an admin user for accessing the admin panel:

```bash
python -c "
from app_flask import create_app
from models import db, User, UserRole
from auth_utils import hash_password

app = create_app()
with app.app_context():
    admin_user = User(
        email='admin@yourdomain.com',
        password_hash=hash_password('your-admin-password'),
        role=UserRole.ADMIN
    )
    db.session.add(admin_user)
    db.session.commit()
    print('Admin user created successfully!')
"
```

## Step 9: Run the Application

### Development Mode:
```bash
# Using UV
uv run python app.py

# Using pip (with activated virtual environment)
python app.py
```

The application will start on `http://localhost:5000`

### Production Mode:
```bash
# Set production environment
export FLASK_ENV=production  # On macOS/Linux
set FLASK_ENV=production     # On Windows

# Run with Gunicorn (install first: uv add gunicorn)
uv run gunicorn -w 4 -b 0.0.0.0:5000 "app_flask:create_app()"
```

## Step 10: Verify Installation

1. Open your browser and navigate to `http://localhost:5000`
2. You should see the Domain Upgrade Pro SaaS homepage
3. Register a new user account or login with admin credentials
4. Test the domain analysis functionality

## Application Features

- **User Management**: Registration, login, role-based access
- **Domain Analysis**: Keyword extraction and competitor identification
- **Payment Processing**: Stripe and PayPal integration
- **API Management**: Multi-key rotation and credit tracking
- **Admin Panel**: User management, system monitoring, configuration
- **Background Tasks**: Automated API credit monitoring

## Troubleshooting

### Common Issues:

1. **Database Connection Errors**:
   - Ensure PostgreSQL is running
   - Check DATABASE_URL in .env file
   - Verify database user permissions

2. **Missing Dependencies**:
   - Run `uv sync` or `pip install -r pyproject.toml`
   - Check Python version compatibility

3. **API Key Errors**:
   - Verify SERPER_API_KEY is correctly set
   - Check API key validity at serper.dev

4. **Port Already in Use**:
   - Change port in app.py or set PORT environment variable
   - Kill existing processes using the port

### Logs and Debugging:

- Application logs are displayed in the console
- Check database connection in the admin panel
- Monitor API usage in the API Credits section

## Production Deployment

For production deployment:

1. **Security**:
   - Change SECRET_KEY to a strong, unique value
   - Use strong database passwords
   - Enable HTTPS
   - Set FLASK_ENV=production

2. **Database**:
   - Use a managed PostgreSQL service
   - Enable SSL connections
   - Regular backups

3. **Reverse Proxy**:
   - Use Nginx or Apache as reverse proxy
   - Enable SSL/TLS termination
   - Configure proper security headers

4. **Process Management**:
   - Use systemd, supervisor, or Docker
   - Configure auto-restart on failure
   - Monitor resource usage

## Support

For issues and questions:
- Check the troubleshooting section above
- Review application logs for error details
- Ensure all required environment variables are set
- Verify external API services are accessible

## License

[Add your license information here]