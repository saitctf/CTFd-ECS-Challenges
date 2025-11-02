# Fix Alembic Version - Direct Database Fix (Container Restarting)

Since your container keeps restarting, fix this directly in the database.

## Step 1: Stop the Container

First, stop the container so it doesn't keep restarting:

```bash
# Find the container
docker ps | grep ctfd

# Stop it
docker stop <ctfd-container-name>

# OR if using docker-compose
docker-compose stop ctfd
```

## Step 2: Connect to RDS Database

```bash
mysql -h ctfd-db7fc1bf3.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u <username> -p ctfd
```

## Step 3: Check Current State

```sql
-- Check alembic_version table
SELECT * FROM alembic_version;

-- Should be empty, which is why it's trying to create tables
```

## Step 4: Find Latest CTFd Migration Revision

Since you're using `ctfd/ctfd` (latest tag), find the latest revision:

### Option A: Check CTFd GitHub (Easiest)

1. Go to: https://github.com/CTFd/CTFd
2. Navigate to: `migrations/versions/` directory
3. Sort by "Last modified" (descending)
4. Open the most recent `.py` file
5. Look for the line: `revision = "XXXXX"`
6. Copy that revision string

### Option B: Use CTFd API/Releases

Check CTFd's latest release notes or changelog for migration info.

## Step 5: Insert the Revision

Once you have the latest revision (let's say it's `abc123def456`):

```sql
-- Insert the latest revision
INSERT INTO alembic_version (version_num) VALUES ('abc123def456');

-- Verify
SELECT * FROM alembic_version;
```

**You should see ONE row with the revision number.**

## Step 6: If You Can't Find the Exact Revision

### Quick Workaround: Use a Recent Known Revision

Based on CTFd's migration history, recent versions typically end with revisions like:
- CTFd 3.5+: `c5a1b2c3d4e5` format (12 hex characters)
- CTFd 3.6+: `f1a2b3c4d5e6` format

**To find the ACTUAL latest:**
1. Go to: https://github.com/CTFd/CTFd/tree/master/migrations/versions
2. Click on the most recently modified file
3. Click "Raw" to view the file
4. Look for `revision = "..."` near the top

### Alternative: Use Initial Revision (Then Let Migrations Run)

If you're desperate, you can insert the initial revision and let it "upgrade":

```sql
-- Insert initial revision
INSERT INTO alembic_version (version_num) VALUES ('8369118943a1');

-- This will make Alembic think it needs to upgrade
-- But since tables exist, you'll need to handle conflicts
```

**This is NOT recommended** - it will try to create tables that exist.

## Step 7: Find Latest Revision from GitHub (Detailed)

Here's how to get it:

1. **Go to CTFd GitHub**: https://github.com/CTFd/CTFd
2. **Click**: `migrations` folder
3. **Click**: `versions` folder  
4. **Sort by**: Last modified (click the column header)
5. **Open**: The most recent `.py` file
6. **Find**: Line with `revision = "..."` (usually around line 12-14)
7. **Copy**: The value between quotes

Example:
```python
revision = "c5a1b2c3d4e5f6"
```

Then use that in your SQL:
```sql
INSERT INTO alembic_version (version_num) VALUES ('c5a1b2c3d4e5f6');
```

## Step 8: Restart Container

After inserting the revision:

```bash
# Start the container again
docker start <ctfd-container-name>
# OR
docker-compose start ctfd
```

## Alternative: Clone CTFd Locally to Find Revision

If you want to find it programmatically:

```bash
# Clone CTFd repo locally
git clone https://github.com/CTFd/CTFd.git /tmp/ctfd

# Find latest migration revision
cd /tmp/ctfd/migrations/versions
ls -t *.py | head -1 | xargs grep "^revision" | head -1 | sed "s/revision = //" | sed "s/['\"]//g"
```

This will output the latest revision number you can use.

## Quick SQL Fix (If You Know Your CTFd Version)

If you know what version of CTFd you're running, you can look up the head revision for that version. Common recent head revisions:

- **CTFd 3.6.0**: Check GitHub for this version's migrations
- **CTFd 3.5.0**: Check GitHub for this version's migrations

**To find your version** (if you can access logs before it crashes):
- Check Docker image tag: `docker images | grep ctfd`
- Or check what was deployed

## Final Checklist

- [ ] Container is stopped
- [ ] Connected to RDS database  
- [ ] Found latest revision from CTFd GitHub
- [ ] Inserted revision into `alembic_version` table
- [ ] Verified: `SELECT * FROM alembic_version;` shows one row
- [ ] Restarted container
- [ ] Container starts successfully

## If Still Failing

If after inserting the revision it still fails, check:
1. Did you use the correct revision format? (12 hex characters)
2. Is there only ONE row in alembic_version?
3. Are there any other migration-related tables?

```sql
-- Check for other version tables
SHOW TABLES LIKE '%version%';
SHOW TABLES LIKE '%alembic%';
```

