-- Optional: tag scans as windows vs android (API + list views)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS log_platform VARCHAR(16);
