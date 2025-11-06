# Email Security Monitor - Outlook Plugin

AI-powered email security monitoring system that integrates seamlessly with Microsoft Outlook to detect spam and phishing emails in real-time using machine learning and OpenAI.

## Colab Notebook for AI Model
https://colab.research.google.com/drive/1C8GgH9_BexFJlsRc5ij4B9dmIha0bI-6?usp=sharing

## Features

- **Real-time Email Analysis**: Instant detection of spam and phishing emails
- **Dual AI Detection**: Combines ML model + OpenAI GPT-4 for enhanced accuracy
- **70% Confidence Threshold**: Only shows notifications when confidence exceeds 70%
- **Outlook Integration**: Seamless plugin experience within Outlook
- **Admin Authentication**: Secure JWT-based authentication for admin dashboard
- **SOC Dashboard**: Comprehensive security operations center dashboard
- **User Reports**: Track spam/phishing per user email
- **Threat Intelligence**: Database-driven threat analysis and reporting
- **Multi-platform Support**: Works on Outlook Desktop, Web, and Mobile
- **Automated Actions**: Delete, move to junk, or report threats automatically
- **PostgreSQL Database**: Robust data storage with Docker support

## Quick Start with Docker (Recommended)

### Prerequisites
- Docker and Docker Compose installed
- OpenAI API Key (optional, for enhanced detection)

### Step 1: Clone and Setup
```bash
git clone <repository-url>
cd outlookplugin
```

### Step 2: Configure Environment Variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your configuration
nano .env
```

**Important**: Add your OpenAI API key in `.env`:
```env
OPENAI_API_KEY=your-actual-openai-api-key-here
```

### Step 3: Start with Docker Compose
```bash
# Start all services (PostgreSQL + Application)
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

The application will be available at:
- **Dashboard**: http://localhost:5000
- **Admin Login**: http://localhost:5000/login
- **API Docs**: http://localhost:5000/docs

### Step 4: Access Admin Dashboard
- **URL**: http://localhost:5000/login
- **Default Username**: `admin`
- **Default Password**: `admin123`

⚠️ **IMPORTANT**: Change the default admin password immediately in production!

## Manual Installation (Without Docker)

### Step 1: Create Virtual Environment
```bash
python -m venv venv
```

### Step 2: Activate Virtual Environment
```bash
# On Linux/Mac
source venv/bin/activate

# On Windows
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Setup PostgreSQL Database
Install PostgreSQL and create a database:
```bash
createdb email_security
psql email_security < init-db.sql
```

### Step 5: Configure Environment
```bash
cp .env.example .env
# Edit .env with your PostgreSQL credentials and OpenAI API key
```

### Step 6: Run Application
```bash
uvicorn main:app --host 0.0.0.0 --port 5000 --reload
```

## Outlook Add-in Setup

### Step 1: Update Manifest
Edit `manifest.xml` and update these URLs to your deployment:
```xml
<IconUrl DefaultValue="https://your-domain.com/assets/icon-64.png"/>
<SourceLocation DefaultValue="https://your-domain.com/plugin.html"/>
```

### Step 2: Deploy to Outlook

**For Microsoft 365:**
1. Go to Microsoft 365 Admin Center
2. Navigate to Settings → Integrated apps
3. Click "Upload custom apps"
4. Upload the `manifest.xml` file
5. Assign to users or groups

**For Outlook Desktop (Sideload):**
1. Open Outlook
2. Go to File → Get Add-ins
3. Click "My add-ins"
4. Under "Custom add-ins", click "Add from file"
5. Select `manifest.xml`

## API Endpoints

### Public Endpoints
- `POST /api/analyze-email` - Analyze email for threats
- `POST /api/report-threat` - Report a threat manually
- `GET /health` - Health check endpoint

### Admin Endpoints (Requires Authentication)
- `POST /api/admin/login` - Login and get JWT token
- `GET /api/admin/verify` - Verify JWT token
- `POST /api/admin/create-user` - Create new admin user
- `GET /api/user-reports` - Get user-specific reports
- `GET /api/email-data` - Get detailed email analysis data
- `GET /api/dashboard-data` - Get dashboard metrics

## Configuration

### Environment Variables
```env
# Database
DB_NAME=email_security
DB_USER=admin
DB_PASSWORD=securepassword123
DB_HOST=postgres  # or localhost for manual setup
DB_PORT=5432

# OpenAI
OPENAI_API_KEY=your-openai-api-key-here

# JWT Authentication
JWT_SECRET_KEY=your-super-secret-jwt-key
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Database Schema
The database is automatically initialized with:
- `admin_users` - Admin user accounts
- `email_analysis` - Email analysis results
- `threat_reports` - Manually reported threats
- `system_metrics` - System performance metrics
- `spam_database` - Confirmed spam emails
- `phishing_database` - Confirmed phishing emails

## AI Detection Logic

The system uses a **dual-layer approach**:

1. **ML Model** (40% weight)
   - TensorFlow-based neural network
   - Trained on email datasets
   - TF-IDF vectorization

2. **OpenAI GPT-4** (60% weight)
   - Advanced natural language understanding
   - Context-aware threat detection
   - Reasoning and explanation

3. **Combined Prediction**
   - Weighted average of both models
   - Confidence boost when models agree
   - **70% threshold** for user notifications

## Security Features

- JWT-based authentication for admin access
- Bcrypt password hashing
- Protected API endpoints
- SQL injection prevention with parameterized queries
- CORS configuration for Outlook integration

## Development

### Run Tests
```bash
pytest tests/
```

### View Logs
```bash
# Docker
docker-compose logs -f app

# Manual
# Logs are printed to stdout
```

### Database Migrations
```bash
# Connect to database
docker-compose exec postgres psql -U admin -d email_security

# Or for manual setup
psql -U admin -d email_security
```

## Troubleshooting

### Docker Issues
```bash
# Rebuild containers
docker-compose build --no-cache

# Reset database
docker-compose down -v
docker-compose up -d
```

### Connection Issues
- Ensure PostgreSQL is running
- Check database credentials in `.env`
- Verify firewall settings

### OpenAI Issues
- Verify API key is correct
- Check API quota and usage
- System falls back to ML-only if OpenAI fails

## Production Deployment

1. **Change Default Credentials**
   ```sql
   UPDATE admin_users SET hashed_password = '$2b$12$...' WHERE username = 'admin';
   ```

2. **Set Strong JWT Secret**
   ```bash
   openssl rand -hex 32
   ```

3. **Enable HTTPS**
   - Use reverse proxy (nginx/Apache)
   - Obtain SSL certificate (Let's Encrypt)

4. **Configure CORS**
   - Update `allow_origins` in `main.py`
   - Restrict to your domain only

5. **Monitor Resources**
   - Set up logging and monitoring
   - Configure database backups

## Architecture

```
┌─────────────────┐
│  Outlook Client │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   FastAPI App   │
│   (Port 5000)   │
└────────┬────────┘
         │
         ├──────────► ML Model (TensorFlow)
         │
         ├──────────► OpenAI API (GPT-4)
         │
         ▼
┌─────────────────┐
│   PostgreSQL    │
│   (Port 5432)   │
└─────────────────┘
```


MIT License

Copyright (c) 2025 Hariharan Palanisamy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

_



