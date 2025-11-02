# Fix Plugin Migration Version

## Problem
The error shows: `ResolutionError: No such revision or branch 'a1b2c3d4e5f6'`

This means there's an incorrect revision stored in the plugin's version table. CTFd plugins have their own migration version tracking separate from the main CTFd migrations.

## Solution: Update Plugin Version Table

### Step 1: Connect to Database

```bash
mysql -h ctfd-db7fc1bf3.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u <username> -p ctfd
```

### Step 2: Find Plugin Version Table

CTFd plugins typically store versions in a table. Common patterns:
- `alembic_version_ecs_challenges`
- `ecs_challenges_alembic_version`
- Or in the main `alembic_version` table with a plugin identifier

Check what exists:
```sql
SHOW TABLES LIKE '%version%';
SHOW TABLES LIKE '%alembic%';
SHOW TABLES LIKE '%ecs%';
```

### Step 3: Check Current Plugin Version

```sql
-- Try these queries to find the plugin version table:
SELECT * FROM alembic_version_ecs_challenges;
-- OR
SELECT * FROM alembic_version WHERE version_num = 'a1b2c3d4e5f6';
-- OR
SELECT * FROM alembic_version;
```

### Step 4: Find the Correct Latest Revision

The ECS challenges plugin has these migrations:
1. `15277440466a` (base - down_revision = None)
2. `d636e6a85f63`
3. `fd89efbba1d3`
4. `b4fb43494ffc`
5. `6f2773029d86`
6. `0012477fe0a8`
7. `561bdf73025e`
8. `8fb71d82c1e7` (latest)

### Step 5: Update to Correct Revision

**Option A: If table exists (alembic_version_ecs_challenges)**
```sql
-- Delete the incorrect revision
DELETE FROM alembic_version_ecs_challenges WHERE version_num = 'a1b2c3d4e5f6';

-- Insert the latest revision
INSERT INTO alembic_version_ecs_challenges (version_num) VALUES ('8fb71d82c1e7');
```

**Option B: If using main alembic_version table with plugin identifier**
```sql
-- Update the revision for ecs_challenges plugin
UPDATE alembic_version 
SET version_num = '8fb71d82c1e7' 
WHERE version_num = 'a1b2c3d4e5f6' 
   OR plugin = 'ecs_challenges';
```

**Option C: If table doesn't exist, set to base revision**
```sql
-- Start from the beginning
INSERT INTO alembic_version_ecs_challenges (version_num) VALUES ('15277440466a');

-- This will let Alembic apply all migrations from the start
```

### Step 6: Alternative - Check What Revision Your Database Schema Matches

If you're not sure which revision to use, check your schema state:

```sql
-- Check if guide column exists (from latest migration)
SHOW COLUMNS FROM ecs_challenge LIKE 'guide';

-- If guide column exists and is NOT NULL with default, you're at: 8fb71d82c1e7
-- If guide column exists and is NULL, you're at: 561bdf73025e
-- If guide_enabled exists in ecs_config, you're at least at: 561bdf73025e
```

Then set the version accordingly.

### Step 7: Restart Container

```bash
docker-compose restart ctfd
```

## If Still Failing: Reset Plugin Migrations

If the plugin is in a bad state, you can reset it:

```sql
-- Delete plugin version table (if it exists separately)
DROP TABLE IF EXISTS alembic_version_ecs_challenges;

-- Or delete just the plugin's entry
DELETE FROM alembic_version WHERE version_num = 'a1b2c3d4e5f6';
```

Then restart - CTFd should recreate it and apply migrations from the beginning.

## Quick Fix Command Summary

```sql
-- 1. Find and delete incorrect revision
DELETE FROM alembic_version_ecs_challenges WHERE version_num = 'a1b2c3d4e5f6';
-- OR if in main table:
DELETE FROM alembic_version WHERE version_num = 'a1b2c3d4e5f6';

-- 2. Insert latest revision (if schema is up to date)
INSERT INTO alembic_version_ecs_challenges (version_num) VALUES ('8fb71d82c1e7');

-- OR insert base revision (to let migrations run from start)
INSERT INTO alembic_version_ecs_challenges (version_num) VALUES ('15277440466a');
```

