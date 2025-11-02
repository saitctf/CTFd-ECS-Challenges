# Quick Fix: Restore Alembic Version After Emptying Table

## The Problem
You emptied `alembic_version`, so Alembic thinks the database is empty and tries to create tables that already exist.

## FASTEST SOLUTION: Use Alembic Stamp (Recommended)

If you have access to your CTFd container, this is the easiest:

```bash
# Find your CTFd container name
docker ps | grep ctfd

# Run Alembic stamp to mark database as up-to-date
docker exec <ctfd-container-name> alembic -c /opt/CTFd/migrations/alembic.ini stamp head
```

This tells Alembic "the database is already at the latest version" without running migrations.

## ALTERNATIVE: Manual SQL Fix

If you can't use Alembic stamp, find the latest revision and insert it manually:

### Step 1: Find Latest Migration Revision

**Option A: From CTFd container**
```bash
# Get latest migration file
docker exec <ctfd-container> ls -t /opt/CTFd/migrations/versions/*.py | head -1

# Extract revision from that file
docker exec <ctfd-container> grep "^revision" /opt/CTFd/migrations/versions/<filename>.py
```

**Option B: Check CTFd GitHub**
1. Go to: https://github.com/CTFd/CTFd/tree/master/migrations/versions
2. Find the latest migration file (sorted by date)
3. Open it and look for `revision = "..."`

**Option C: Quick Python script**
```bash
docker exec <ctfd-container> python3 -c "
import os, re
files = sorted([f for f in os.listdir('/opt/CTFd/migrations/versions') if f.endswith('.py')])
if files:
    latest = files[-1]
    with open(f'/opt/CTFd/migrations/versions/{latest}') as f:
        match = re.search(r'^revision\s*=\s*[\"\\']([^\"\\']+)[\"\\']', f.read(), re.MULTILINE)
        if match:
            print(match.group(1))
"
```

### Step 2: Insert the Revision

Once you have the latest revision (e.g., `abc123def456`):

```bash
# Connect to your RDS database
mysql -h ctfd-db7fc1bf3.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u <username> -p ctfd
```

Then:
```sql
-- Insert the latest revision
INSERT INTO alembic_version (version_num) VALUES ('<latest-revision-from-step-1>');

-- Verify it was inserted
SELECT * FROM alembic_version;
```

### Step 3: Restart CTFd

```bash
docker restart <ctfd-container>
# OR
docker-compose restart ctfd
```

## If You Don't Know the Exact Revision

If you can't determine the exact revision, you can try to infer it from the error message. The error showed it's trying to run `8369118943a1_initial_revision.py`, which is the INITIAL migration. Your database is likely much further along.

**Workaround**: Use a recent CTFd version's head revision. Check:
- CTFd release notes for migration info
- Or use Alembic to check what migrations exist:

```bash
docker exec <ctfd-container> bash -c "cd /opt/CTFd && alembic heads"
```

This will show you the current head revision(s).

## Emergency Workaround (Use with Caution)

If you're stuck and need CTFd to start immediately, you can temporarily bypass migrations by:

1. **Comment out the upgrade call** in CTFd's `__init__.py` (NOT RECOMMENDED - breaks future migrations)
2. **Or manually stamp to a revision you know exists** based on your CTFd version

**To find your CTFd version:**
```bash
docker exec <ctfd-container> python3 -c "import CTFd; print(CTFd.__version__)"
```

Then look up what migrations that version should have.

## Important Notes

- **Backup your database first!**
- The `alembic_version` table should have exactly ONE row
- After fixing the main CTFd version, you may still need to handle plugin versions separately
- Using `alembic stamp head` is the safest method if available

