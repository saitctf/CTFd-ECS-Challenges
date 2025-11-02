# Fix: Dropped alembic_version Table

## Problem
You dropped the `alembic_version` table, so Alembic thinks the database is empty and tries to create tables that already exist.

## Quick Fix

### Step 1: Stop the Container

```bash
docker-compose stop ctfd
# OR
docker stop $(docker ps -q --filter "name=ctfd")
```

### Step 2: Connect to Database

```bash
mysql -h ctfd-db7fc1bf3.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u <username> -p ctfd
```

### Step 3: Check if Table Exists

```sql
-- Check if alembic_version table exists
SHOW TABLES LIKE 'alembic_version';

-- Check its contents
SELECT * FROM alembic_version;
```

If the table doesn't exist, Alembic will recreate it automatically, but it will be empty.

### Step 4: Create Table (if it doesn't exist)

```sql
-- Create the table if it doesn't exist
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL PRIMARY KEY
);
```

### Step 5: Find and Insert Latest CTFd Revision

You need to find the latest CTFd migration revision. Use one of these methods:

**Method A: Use the script (if you have it locally)**
```bash
./get_latest_revision.sh
```

**Method B: Check CTFd GitHub directly**
1. Go to: https://github.com/CTFd/CTFd/tree/master/migrations/versions
2. Sort by "Last modified" (most recent first)
3. Open the most recent `.py` file
4. Find: `revision = "XXXXX"` (around line 12-14)
5. Copy the revision (12 hex characters)

**Method C: Quick SQL workaround - Insert a recent known revision**

If you can't find it immediately, you can temporarily insert a revision and update it later. But you need the actual latest.

### Step 6: Insert the Latest Revision

Once you have the latest revision (let's say it's `abc123def456`):

```sql
-- Make sure table exists
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL PRIMARY KEY
);

-- Insert the latest revision
INSERT INTO alembic_version (version_num) VALUES ('<latest-revision>');

-- Verify
SELECT * FROM alembic_version;
```

**Important**: You must use the actual latest revision from CTFd's migrations, not a placeholder!

### Step 7: Restart Container

```bash
docker-compose start ctfd
# OR
docker start <ctfd-container>
```

## Alternative: Use Alembic Stamp (If Container is Accessible)

If you can temporarily get container access, use Alembic stamp:

```bash
# Run Alembic stamp to mark database as current
docker exec <ctfd-container> alembic -c /opt/CTFd/migrations/alembic.ini stamp head
```

This is the easiest method if available.

## Finding the Latest Revision Manually

Since your container keeps crashing, here's how to find it without container access:

1. **Go to CTFd GitHub**: https://github.com/CTFd/CTFd
2. **Navigate to**: `migrations/versions/` folder
3. **Sort files by**: Date modified (newest first)
4. **Click on**: The most recently modified `.py` file
5. **Look for**: Line that says `revision = "..."` (usually line 12-14)
6. **Copy**: The value inside the quotes (12 hex characters like `a1b2c3d4e5f6`)

That's the revision you need to insert.

## Emergency: If You Can't Find the Exact Revision

If you're desperate and need CTFd running immediately:

1. Check what CTFd version you're using (from Dockerfile: `ctfd/ctfd`)
2. Check CTFd's release notes for that version
3. Look up what the head revision was for that version

**But this is risky** - it's better to find the actual latest revision.

## Important Notes

- **The `alembic_version` table must have exactly ONE row**
- **The revision must match a migration file that actually exists in CTFd**
- **After fixing, restart the container**
- **You may also need to fix plugin version tables separately**

## After Fixing Main CTFd Version

Don't forget to also check/fix plugin versions if needed:
- `alembic_version_ecs_challenges` (for ECS plugin)
- Any other plugin version tables

