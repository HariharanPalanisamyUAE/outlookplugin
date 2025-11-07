-- Initialize database with admin user and tables

-- Create admin_users table
CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_superuser BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create email_analysis table
CREATE TABLE IF NOT EXISTS email_analysis (
    id SERIAL PRIMARY KEY,
    sender TEXT,
    subject TEXT,
    body TEXT,
    prediction TEXT,
    confidence FLOAT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action_taken TEXT,
    user_email TEXT,
    openai_analysis TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create threat_reports table
CREATE TABLE IF NOT EXISTS threat_reports (
    id SERIAL PRIMARY KEY,
    sender TEXT,
    subject TEXT,
    threat_type TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'open',
    user_email TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create system_metrics table
CREATE TABLE IF NOT EXISTS system_metrics (
    id SERIAL PRIMARY KEY,
    total_emails INTEGER,
    spam_detected INTEGER,
    phishing_detected INTEGER,
    threats_blocked INTEGER,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create spam_database table
CREATE TABLE IF NOT EXISTS spam_database (
    id SERIAL PRIMARY KEY,
    email_id TEXT UNIQUE,
    sender TEXT,
    subject TEXT,
    email_text TEXT,
    user_email TEXT,
    accuracy TEXT,
    added_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Create phishing_database table
CREATE TABLE IF NOT EXISTS phishing_database (
    id SERIAL PRIMARY KEY,
    email_id TEXT UNIQUE,
    sender TEXT,
    subject TEXT,
    email_text TEXT,
    user_email TEXT,
    accuracy TEXT,
    added_timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Create email_cc table
CREATE TABLE IF NOT EXISTS email_cc (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES email_analysis(id) ON DELETE CASCADE,
    cc_email TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create email_bcc table
CREATE TABLE IF NOT EXISTS email_bcc (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES email_analysis(id) ON DELETE CASCADE,
    bcc_email TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create email_recipients table
CREATE TABLE IF NOT EXISTS email_recipients (
    id SERIAL PRIMARY KEY,
    email_id INTEGER REFERENCES email_analysis(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_email_analysis_timestamp ON email_analysis(timestamp);
CREATE INDEX IF NOT EXISTS idx_email_analysis_prediction ON email_analysis(prediction);
CREATE INDEX IF NOT EXISTS idx_email_analysis_user_email ON email_analysis(user_email);
CREATE INDEX IF NOT EXISTS idx_threat_reports_timestamp ON threat_reports(timestamp);
CREATE INDEX IF NOT EXISTS idx_threat_reports_user_email ON threat_reports(user_email);
CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS idx_admin_users_email ON admin_users(email);

-- Insert default admin user
-- Password: admin123 (hashed using bcrypt)
-- Note: Change this password immediately in production!
INSERT INTO admin_users (username, email, hashed_password, full_name, is_superuser)
VALUES (
    'admin',
    'admin@emailsecurity.com',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5aeWG7xJbPQKK',
    'System Administrator',
    TRUE
)
ON CONFLICT (username) DO NOTHING;

-- Create a view for easy dashboard queries
CREATE OR REPLACE VIEW dashboard_summary AS
SELECT
    DATE(timestamp) as date,
    COUNT(*) as total_emails,
    COUNT(CASE WHEN prediction = 'spam' THEN 1 END) as spam_count,
    COUNT(CASE WHEN prediction = 'phishing' THEN 1 END) as phishing_count,
    COUNT(CASE WHEN prediction IN ('spam', 'phishing') THEN 1 END) as threats_blocked,
    AVG(confidence) as avg_confidence
FROM email_analysis
GROUP BY DATE(timestamp)
ORDER BY date DESC;
