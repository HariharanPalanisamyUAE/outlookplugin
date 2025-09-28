from fastapi import FastAPI, Request, Body, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import joblib
import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import threading
import time
import os
from typing import Dict, Any
import asyncio
from contextlib import asynccontextmanager
from fastapi.templating import Jinja2Templates
import tensorflow as tf
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file
# Database configuration
DB_CONFIG = {
    'dbname': os.getenv('DB_NAME', 'DB_NAME'),
    'user': os.getenv('DB_USER', 'DB_USER'),
    'password': os.getenv('DB_PASSWORD', 'DB_PASSWORD'),
    'host': os.getenv('DB_HOST', 'HOST'),
    'port': os.getenv('DB_PORT', 'PORt')
}

# Global variables for model components
model = None
tfidf = None
label_encoder = None

def get_pg_connection():
    """Get PostgreSQL database connection"""
    return psycopg2.connect(
        dbname=DB_CONFIG['dbname'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port']
    )

def load_model_components():
    """Load trained model and preprocessors"""
    global model, tfidf, label_encoder
    try:
       
        model = tf.keras.models.load_model('email_security_model.h5')
        tfidf = joblib.load('tfidf_vectorizer.pkl')
        label_encoder = joblib.load('label_encoder.pkl')
        print("Model loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        model, tfidf, label_encoder = None, None, None
        return False

def init_db():
    """Initialize PostgreSQL database with required tables"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        # Email analysis logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_analysis (
                id SERIAL PRIMARY KEY,
                sender TEXT,
                subject TEXT,
                body TEXT,
                prediction TEXT,
                confidence FLOAT,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                action_taken TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')
        
        # Threat reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_reports (
                id SERIAL PRIMARY KEY,
                sender TEXT,
                subject TEXT,
                threat_type TEXT,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                status TEXT DEFAULT 'open',
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')
        
        # System metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id SERIAL PRIMARY KEY,
                total_emails INTEGER,
                spam_detected INTEGER,
                phishing_detected INTEGER,
                threats_blocked INTEGER,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email_analysis_timestamp ON email_analysis(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_reports_timestamp ON threat_reports(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_email_analysis_prediction ON email_analysis(prediction)')
        
        conn.commit()
        cursor.close()
        conn.close()
        print("Database initialized successfully!")
        return True
    except Exception as e:
        print(f"Error initializing database: {e}")
        return False

# Background task for metrics collection
async def collect_metrics():
    """Background task to collect and store system metrics"""
    while True:
        try:
            conn = get_pg_connection()
            cursor = conn.cursor()
            
            # Get current counts
            cursor.execute('SELECT COUNT(*) FROM email_analysis')
            total_emails = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM email_analysis WHERE prediction='spam'")
            spam_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM email_analysis WHERE prediction='phishing'")
            phishing_count = cursor.fetchone()[0]
            
            # Insert metrics
            cursor.execute('''
                INSERT INTO system_metrics 
                (total_emails, spam_detected, phishing_detected, threats_blocked, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            ''', (total_emails, spam_count, phishing_count, 
                  spam_count + phishing_count, datetime.now()))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"Metrics collection error: {e}")
        
        await asyncio.sleep(300)  # Run every 5 minutes

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager"""
    # Startup
    print("Starting up...")
    if not init_db():
        print("Warning: Database initialization failed")
    
    if not load_model_components():
        print("Warning: Model loading failed")
    
    # Start background metrics collection
    metrics_task = asyncio.create_task(collect_metrics())
    
    yield
    
    # Shutdown
    print("Shutting down...")
    metrics_task.cancel()

# Create FastAPI app
app = FastAPI(
    title="Email Security Monitoring API",
    description="SOC Dashboard for Email Spam and Phishing Detection",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for Outlook plugin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Pydantic models for request validation
from pydantic import BaseModel
from typing import Optional

class EmailAnalysisRequest(BaseModel):
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    timestamp: Optional[str] = None

class ThreatReportRequest(BaseModel):
    sender: Optional[str] = None
    subject: Optional[str] = None
    timestamp: Optional[str] = None

class ActionLogRequest(BaseModel):
    action: str

# API Endpoints

@app.post("/api/analyze-email")
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email for spam/phishing detection with enhanced data storage"""
    try:
        email_text = f"{request.subject or ''} {request.body or ''}"
        
        if not model or not tfidf or not label_encoder:
            raise HTTPException(status_code=500, detail="Model not loaded")
        
        # Preprocess and predict
        email_tfidf = tfidf.transform([str(email_text)]).toarray()
        prediction_probs = model.predict(email_tfidf)[0]
        predicted_class = np.argmax(prediction_probs)
        confidence = float(prediction_probs[predicted_class])
        
        prediction = label_encoder.inverse_transform([predicted_class])[0]
        
        # Log to PostgreSQL database with enhanced data
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        try:
            # Insert main email analysis
            cursor.execute('''
                INSERT INTO email_analysis 
                (sender, subject, body, prediction, confidence, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            ''', (request.sender, request.subject, request.body, 
                  prediction, confidence, datetime.now()))
            
            email_id = cursor.fetchone()[0]
            
            # Store CC recipients if provided
            if hasattr(request, 'cc') and request.cc:
                cc_emails = [email.strip() for email in request.cc.split(',') if email.strip()]
                for cc_email in cc_emails:
                    cursor.execute('''
                        INSERT INTO email_cc (email_id, cc_email)
                        VALUES (%s, %s)
                    ''', (email_id, cc_email))
            
            # Store BCC recipients if provided
            if hasattr(request, 'bcc') and request.bcc:
                bcc_emails = [email.strip() for email in request.bcc.split(',') if email.strip()]
                for bcc_email in bcc_emails:
                    cursor.execute('''
                        INSERT INTO email_bcc (email_id, bcc_email)
                        VALUES (%s, %s)
                    ''', (email_id, bcc_email))
            
            conn.commit()
            
        finally:
            cursor.close()
            conn.close()
        
        return {
            'prediction': prediction,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'email_id': email_id
        }
        
    except Exception as e:
        print(f"Error in analyze_email: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/api/report-threat")
async def report_threat(request: ThreatReportRequest):
    """Report a threat manually"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO threat_reports 
                (sender, subject, threat_type, timestamp)
                VALUES (%s, %s, %s, %s)
            ''', (request.sender, request.subject, 
                  'manual_report', datetime.now()))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        
        return {'status': 'success'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/log-action")
async def log_action(request: ActionLogRequest):
    """Log user action on email"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE email_analysis 
                SET action_taken = %s
                WHERE timestamp = (SELECT MAX(timestamp) FROM email_analysis)
            ''', (request.action,))
            conn.commit()
        finally:
            cursor.close()
            conn.close()
        
        return {'status': 'success'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """SOC Dashboard homepage"""
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/api/dashboard-data")
async def dashboard_data():
    """Get dashboard metrics and data"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get today's metrics
        today = datetime.now().date()
        
        # Email analysis stats
        cursor.execute('''
            SELECT prediction, COUNT(*) as count
            FROM email_analysis 
            WHERE DATE(timestamp) = %s
            GROUP BY prediction
        ''', (today,))
        email_stats = {row['prediction']: row['count'] for row in cursor.fetchall()}
        
        # Recent threats
        cursor.execute('''
            SELECT sender, subject, threat_type, timestamp, status
            FROM threat_reports 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        recent_threats = [dict(row) for row in cursor.fetchall()]
        
        # Hourly activity (last 24 hours)
        cursor.execute('''
            SELECT EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as count
            FROM email_analysis 
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY EXTRACT(HOUR FROM timestamp)
            ORDER BY hour
        ''')
        hourly_activity = {str(int(row['hour'])): row['count'] for row in cursor.fetchall()}
        
        cursor.close()
        conn.close()
        
        return {
            'email_stats': email_stats,
            'recent_threats': recent_threats,
            'hourly_activity': hourly_activity,
            'total_processed': sum(email_stats.values()),
            'threats_blocked': email_stats.get('spam', 0) + email_stats.get('phishing', 0)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/plugin", response_class=HTMLResponse)
async def read_item(request: Request):
        return templates.TemplateResponse("plugin.html", {"request": request, "message": "Hello from Jinja2!"})
@app.get("/api/email-data")
async def get_email_data(
    limit: int = 100,
    offset: int = 0,
    date_filter: str = "today",  # today, week, month, all
    prediction_filter: str = "all"  # all, spam, phishing, safe
):
    """Get email analysis data for dashboard table with filtering options"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Build dynamic WHERE clause based on filters
        where_conditions = []
        params = []
        
        # Date filtering
        if date_filter == "today":
            where_conditions.append("timestamp >= CURRENT_DATE")
        elif date_filter == "week":
            where_conditions.append("timestamp >= CURRENT_DATE - INTERVAL '7 days'")
        elif date_filter == "month":
            where_conditions.append("timestamp >= CURRENT_DATE - INTERVAL '30 days'")
        # 'all' means no date filter
        
        # Prediction filtering
        if prediction_filter != "all":
            where_conditions.append("prediction = %s")
            params.append(prediction_filter)
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        # Enhanced query with better data handling
        query = f'''
            SELECT 
                TO_CHAR(timestamp, 'HH24:MI') as time,
                TO_CHAR(timestamp, 'YYYY-MM-DD') as date,
                subject as email_title,
                prediction,
                confidence as confidence_percent,
                sender,
                body,
                action_taken,
                timestamp,
                id,
                -- Extract user email if available, otherwise use default
                COALESCE(
                    (SELECT DISTINCT recipient_email FROM email_recipients WHERE email_id = email_analysis.id LIMIT 1),
                    'user@company.com'
                ) as user_email,
                -- Extract CC recipients
                (
                    SELECT STRING_AGG(cc_email, ', ') 
                    FROM email_cc 
                    WHERE email_id = email_analysis.id
                ) as cc,
                -- Extract BCC recipients  
                (
                    SELECT STRING_AGG(bcc_email, ', ') 
                    FROM email_bcc 
                    WHERE email_id = email_analysis.id
                ) as bcc
            FROM email_analysis 
            {where_clause}
            ORDER BY timestamp DESC 
            LIMIT %s OFFSET %s
        '''
        
        params.extend([limit, offset])
        cursor.execute(query, params)
        
        emails = []
        for row in cursor.fetchall():
            # Determine prediction display with proper casing
            prediction_display = "Unknown"
            if row['prediction']:
                pred = row['prediction'].lower()
                if pred == 'ham':
                    prediction_display = "Safe"
                elif pred == 'spam':
                    prediction_display = "Spam"
                elif pred == 'phishing':
                    prediction_display = "Phishing"
                else:
                    prediction_display = row['prediction'].title()
            
            emails.append({
                'time': row['time'],
                'date': row['date'],
                'title': row['email_title'] or 'No Subject',
                'prediction': prediction_display,
                'accuracy': f"{row['confidence_percent'] or 0}%",
                'userEmail': row['user_email'],
                'sender': row['sender'] or 'Unknown',
                'cc': row['cc'] or '',
                'bcc': row['bcc'] or '',
                'emailText': row['body'] or '',
                'id': f"email_{row['timestamp'].strftime('%Y%m%d_%H%M%S')}" if row['timestamp'] else f"email_{row['id']}",
                'actionTaken': row['action_taken'] or 'None',
                'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None
            })
        
        # Get total count for pagination
        count_query = f'''
            SELECT COUNT(*) as total
            FROM email_analysis 
            {where_clause}
        '''
        cursor.execute(count_query, params[:-2])  # Exclude limit and offset
        total_count = cursor.fetchone()['total']
        
        cursor.close()
        conn.close()
        
        return {
            'emails': emails,
            'total': total_count,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total_count
        }
        
    except Exception as e:
        print(f"Error in get_email_data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threat-statistics")
async def get_threat_statistics():
    """Get threat statistics for the dashboard"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get today's statistics
        cursor.execute('''
            SELECT 
                COUNT(*) as total_processed,
                COUNT(CASE WHEN prediction = 'spam' THEN 1 END) as spam_count,
                COUNT(CASE WHEN prediction = 'phishing' THEN 1 END) as phishing_count,
                COUNT(CASE WHEN prediction IN ('spam', 'phishing') THEN 1 END) as threats_blocked,
                AVG(confidence) as avg_confidence
            FROM email_analysis 
            WHERE DATE(timestamp) = CURRENT_DATE
        ''')
        
        stats = cursor.fetchone()
        
        # Get hourly activity for the chart
        cursor.execute('''
            SELECT 
                EXTRACT(HOUR FROM timestamp) as hour,
                COUNT(*) as email_count,
                COUNT(CASE WHEN prediction IN ('spam', 'phishing') THEN 1 END) as threat_count
            FROM email_analysis 
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY EXTRACT(HOUR FROM timestamp)
            ORDER BY hour
        ''')
        
        hourly_data = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return {
            'totalProcessed': stats['total_processed'] or 0,
            'spamCount': stats['spam_count'] or 0,
            'phishingCount': stats['phishing_count'] or 0,
            'threatsBlocked': stats['threats_blocked'] or 0,
            'avgConfidence': round(stats['avg_confidence'] * 100, 1) if stats['avg_confidence'] else 0,
            'hourlyActivity': {str(int(row['hour'])): row['email_count'] for row in hourly_data},
            'hourlyThreats': {str(int(row['hour'])): row['threat_count'] for row in hourly_data}
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/add-to-database")
async def add_to_database(request: dict):
    """Add email to spam/phishing database"""
    try:
        email_id = request.get('emailId')
        database_type = request.get('databaseType')  # 'spam' or 'phishing'
        email_data = request.get('emailData')
        
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        # Create spam/phishing database tables if they don't exist
        if database_type == 'spam':
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS spam_database (
                    id SERIAL PRIMARY KEY,
                    email_id TEXT UNIQUE,
                    sender TEXT,
                    subject TEXT,
                    email_text TEXT,
                    user_email TEXT,
                    accuracy TEXT,
                    added_timestamp TIMESTAMPTZ DEFAULT NOW()
                )
            ''')
            
            cursor.execute('''
                INSERT INTO spam_database (email_id, sender, subject, email_text, user_email, accuracy)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (email_id) DO NOTHING
            ''', (
                email_id,
                email_data.get('sender'),
                email_data.get('subject'),
                email_data.get('emailText'),
                email_data.get('userEmail'),
                email_data.get('accuracy')
            ))
            
        elif database_type == 'phishing':
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS phishing_database (
                    id SERIAL PRIMARY KEY,
                    email_id TEXT UNIQUE,
                    sender TEXT,
                    subject TEXT,
                    email_text TEXT,
                    user_email TEXT,
                    accuracy TEXT,
                    added_timestamp TIMESTAMPTZ DEFAULT NOW()
                )
            ''')
            
            cursor.execute('''
                INSERT INTO phishing_database (email_id, sender, subject, email_text, user_email, accuracy)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (email_id) DO NOTHING
            ''', (
                email_id,
                email_data.get('sender'),
                email_data.get('subject'),
                email_data.get('emailText'),
                email_data.get('userEmail'),
                email_data.get('accuracy')
            ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return {'status': 'success', 'message': f'Email added to {database_type} database'}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/database-stats")
async def get_database_stats():
    """Get spam and phishing database statistics"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor()
        
        # Get spam database count
        cursor.execute('SELECT COUNT(*) FROM spam_database')
        spam_count = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        # Get phishing database count
        cursor.execute('SELECT COUNT(*) FROM phishing_database')
        phishing_count = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.close()
        conn.close()
        
        return {
            'spamDatabaseCount': spam_count,
            'phishingDatabaseCount': phishing_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Enhanced dashboard data endpoint
@app.get("/api/dashboard-data")
async def dashboard_data():
    """Enhanced dashboard metrics and data"""
    try:
        conn = get_pg_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get today's metrics
        today = datetime.now().date()
        
        # Email analysis stats
        cursor.execute('''
            SELECT 
                prediction, 
                COUNT(*) as count,
                AVG(confidence) as avg_confidence
            FROM email_analysis 
            WHERE DATE(timestamp) = %s
            GROUP BY prediction
        ''', (today,))
        email_stats = {}
        for row in cursor.fetchall():
            email_stats[row['prediction']] = {
                'count': row['count'],
                'avg_confidence': round(row['avg_confidence'] * 100, 1) if row['avg_confidence'] else 0
            }
        
        # Recent threats with more details
        cursor.execute('''
            SELECT 
                sender, 
                subject, 
                prediction as threat_type, 
                timestamp, 
                confidence,
                action_taken as status
            FROM email_analysis 
            WHERE prediction IN ('spam', 'phishing')
            ORDER BY timestamp DESC 
            LIMIT 10
        ''')
        recent_threats = []
        for row in cursor.fetchall():
            recent_threats.append({
                'sender': row['sender'],
                'subject': row['subject'],
                'threat_type': row['threat_type'],
                'timestamp': row['timestamp'].isoformat() if row['timestamp'] else None,
                'confidence': row['confidence'],
                'status': row['status'] or 'Open'
            })
        
        # Hourly activity (last 24 hours)
        cursor.execute('''
            SELECT 
                EXTRACT(HOUR FROM timestamp) as hour, 
                COUNT(*) as count,
                COUNT(CASE WHEN prediction IN ('spam', 'phishing') THEN 1 END) as threats
            FROM email_analysis 
            WHERE timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY EXTRACT(HOUR FROM timestamp)
            ORDER BY hour
        ''')
        hourly_activity = {}
        hourly_threats = {}
        for row in cursor.fetchall():
            hour = str(int(row['hour']))
            hourly_activity[hour] = row['count']
            hourly_threats[hour] = row['threats']
        
        cursor.close()
        conn.close()
        
        total_processed = sum(stats['count'] for stats in email_stats.values())
        threats_blocked = email_stats.get('spam', {}).get('count', 0) + email_stats.get('phishing', {}).get('count', 0)
        
        return {
            'email_stats': {
                'ham': email_stats.get('ham', {}).get('count', 0),
                'spam': email_stats.get('spam', {}).get('count', 0),
                'phishing': email_stats.get('phishing', {}).get('count', 0)
            },
            'recent_threats': recent_threats,
            'hourly_activity': hourly_activity,
            'hourly_threats': hourly_threats,
            'total_processed': total_processed,
            'threats_blocked': threats_blocked,
            'system_status': {
                'api_server': 'online',
                'database': 'connected',
                'ai_model': 'active' if model else 'inactive',
                'security_engine': 'active'
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))    
# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    model_status = "loaded" if model and tfidf and label_encoder else "not_loaded"
    
    try:
        conn = get_pg_connection()
        conn.close()
        db_status = "connected"
    except:
        db_status = "disconnected"
    
    return {
        "status": "healthy",
        "model_status": model_status,
        "database_status": db_status,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)
