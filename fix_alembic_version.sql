-- Fix Alembic version tracking for ECS Challenges plugin
-- This removes the reference to the non-existent revision 'a1b2c3d4e5f6'
-- and sets it back to the actual latest revision '8fb71d82c1e7'

-- Check if the problematic revision exists and update it
UPDATE alembic_version 
SET version_num = '8fb71d82c1e7' 
WHERE version_num = 'a1b2c3d4e5f6';

-- If the above doesn't match, the version might be stored differently
-- Try this alternative: update any row for ecs_challenges that references a1b2c3d4e5f6
-- Note: Adjust the WHERE clause based on how CTFd stores plugin versions in alembic_version table

