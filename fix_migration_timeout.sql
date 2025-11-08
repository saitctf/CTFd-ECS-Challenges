-- Fix for migration 113uj5m91yf2 - timeout column already exists
-- Run this on your MySQL database to verify and fix the migration state
-- 
-- This script:
-- 1. Verifies the timeout column exists
-- 2. Provides instructions for marking the migration as complete if needed

USE ctfd;

-- Check if the timeout column exists
SELECT 
    COLUMN_NAME,
    DATA_TYPE,
    IS_NULLABLE,
    COLUMN_DEFAULT
FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'ecs_challenge' 
  AND COLUMN_NAME = 'timeout';

-- If the column exists, you can manually mark the migration as applied
-- by inserting the revision into the alembic_version table for the plugin
-- (CTFd uses plugin-specific version tracking)
-- 
-- First, check what version table is used for ecs_challenges plugin:
-- SELECT * FROM alembic_version WHERE version_num LIKE '%ecs%';
-- 
-- Or check the plugin's version table (if it exists):
-- SHOW TABLES LIKE '%ecs%version%';
-- 
-- Then insert the revision (replace 'ecs_challenges' with actual table name if different):
-- INSERT INTO alembic_version_ecs_challenges (version_num) 
-- VALUES ('113uj5m91yf2') 
-- ON DUPLICATE KEY UPDATE version_num = '113uj5m91yf2';

-- Alternative: If the column doesn't exist, add it manually:
-- ALTER TABLE ecs_challenge 
-- ADD COLUMN timeout INT NULL 
-- COMMENT 'Timeout in seconds (NULL means no timeout)';

