# Domain Upgrade Pro SaaS - Local Installation Requirements

Based on analysis of the application codebase, here's the complete list of what you need to run this locally on your computer:

## **System Requirements**
- **Python 3.11 or higher**
- **PostgreSQL 12 or higher** (database server)
- **Git** (to clone the repository)

## **Python Dependencies** (from pyproject.toml)
```
apscheduler>=3.11.0
flask-mail>=0.10.0
flask>=3.1.2
flask-bcrypt>=1.0.1
flask-login>=0.6.3
flask-migrate>=4.1.0
flask-sqlalchemy>=3.1.1
openpyxl>=3.1.5
pandas>=2.3.2
psycopg2-binary>=2.9.10
python-dotenv>=1.1.1
requests>=2.32.5
sqlalchemy>=2.0.43
streamlit>=1.28.0
stripe>=12.5.0
```

## **Required External Services & API Keys**
1. **Serper API Key** (Required for core functionality)
   - Used for Google search integration via serper.dev
   - Required in environment variable: `SERPER_API_KEY`

2. **PostgreSQL Database**
   - Required for user accounts, transactions, search history
   - Needs `DATABASE_URL` environment variable

## **Optional External Services** (for full functionality)
3. **Stripe Account** (for payment processing)
   - `STRIPE_PUBLIC_KEY`
   - `STRIPE_SECRET_KEY` 
   - `STRIPE_WEBHOOK_SECRET`

4. **PayPal Account** (alternative payment processing)
   - `PAYPAL_CLIENT_ID`
   - `PAYPAL_CLIENT_SECRET`
   - `PAYPAL_MODE` (sandbox/live)

5. **SMTP Server** (for email notifications)
   - Standard SMTP configuration variables

## **Environment Variables Needed**
```env
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://user:password@localhost:5432/database_name
SERPER_API_KEY=your-serper-api-key

# Optional for payments
STRIPE_PUBLIC_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
PAYPAL_CLIENT_ID=your-paypal-id
PAYPAL_CLIENT_SECRET=your-paypal-secret
```

## **Run Commands**
**Development:**
```bash
python app.py
```

**Production:**
```bash
gunicorn -w 4 -b 0.0.0.0:5000 "app_flask:create_app()"
```

## **Application Features That Require External Services**
- **Domain analysis** → Needs Serper API
- **User accounts** → Needs PostgreSQL
- **Payments** → Needs Stripe and/or PayPal
- **Background tasks** → Uses APScheduler (included)
- **Excel exports** → Uses openpyxl (included)

## **Minimum Requirements for Basic Functionality**
The core functionality (domain analysis) requires:
- PostgreSQL database
- Serper API key

Payment features are optional if you just want to test the domain analysis capabilities.