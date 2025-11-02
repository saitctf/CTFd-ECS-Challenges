-- Quick fix: Add timeout column to ecs_challenge table
-- Run this on your MySQL database

USE ctfd;

-- Check if column already exists
SELECT COUNT(*) 
FROM information_schema.COLUMNS 
WHERE TABLE_SCHEMA = 'ctfd' 
  AND TABLE_NAME = 'ecs_challenge' 
  AND COLUMN_NAME = 'timeout';

-- Add the column if it doesn't exist
ALTER TABLE ecs_challenge 
ADD COLUMN timeout INT NULL 
COMMENT 'Timeout in seconds (NULL means no timeout)';

-- Verify the column was added
DESCRIBE ecs_challenge;

