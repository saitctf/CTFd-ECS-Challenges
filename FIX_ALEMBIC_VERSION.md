# Fix Alembic Version Table After Emptying It

## Problem
You emptied the `alembic_version` table, causing Alembic to think the database is empty and try to create tables that already exist.

## Solution: Restore the Version Number

### Step 1: Find the Latest CTFd Migration Revision

The latest revision number can be found in CTFd's migrations directory. You need to:

1. **Check what migrations CTFd has:**
```bash
# If you have access to the CTFd container
docker exec <ctfd-container> ls -la /opt/CTFd/migrations/versions/ | tail -5

# Or check the CTFd GitHub repository or your CTFd installation
```

2. **Common ways to find it:**
   - Look at the migration files in `/opt/CTFd/migrations/versions/`
   - Check CTFd's GitHub repository for the latest migration
   - The revision is usually in the filename like `8369118943a1_initial_revision.py`

### Step 2: Connect to Database

```bash
mysql -h ctfd-db7fc1bf3.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u <username> -p ctfd
```

### Step 3: Check Current State

```sql
-- Check if alembic_version table exists
SELECT * FROM alembic_version;

-- Should be empty, which is why it's trying to create tables
```

### Step 4: Find the Latest Migration Revision

**Option A: Check from CTFd container (if accessible)**
```bash
# Get the latest migration file name
docker exec <ctfd-container> ls -t /opt/CTFd/migrations/versions/*.py | head -1

# Then check that file for the revision number
docker exec <ctfd-container> grep "^revision" /opt/CTFd/migrations/versions/<latest-file>.py
```

**Option B: Use Alembic to get current head**
```bash
# From inside CTFd container or environment
docker exec <ctfd-container> alembic -c /opt/CTFd/migrations/alembic.ini current
# Or
docker exec <ctfd-container> alembic -c /opt/CTFd/migrations/alembic.ini heads
```

**Option C: Check CTFd source code/repository**
- Go to CTFd's GitHub: https://github.com/CTFd/CTFd
- Look in `migrations/versions/` directory
- Find the latest file and check its revision number

### Step 5: Insert the Correct Version

Once you know the latest revision (let's say it's `abc123def456`):

```sql
-- Insert the latest revision into alembic_version table
INSERT INTO alembic_version (version_num) VALUES ('abc123def456');
```

**Important:** You need to use the **actual latest revision** from CTFd, not a placeholder!

### Step 6: Alternative - Mark Database as Up-to-Date Without Knowing Exact Version

If you can't find the exact version, you can:

1. **Check what tables exist to infer the schema version:**
```sql
SHOW TABLES;
-- This will show you what tables exist
```

2. **Use Alembic's stamp command** (if accessible):
```bash
# This marks the database as being at a specific revision without running migrations
docker exec <ctfd-container> alembic -c /opt/CTFd/migrations/alembic.ini stamp head
```

### Step 7: If Tables Already Exist - Manual Stamp

If you can't use Alembic's stamp command, you need to find the revision manually. 

**Quick workaround - Get revision from error message:**
Looking at your error, it mentions `/opt/CTFd/migrations/versions/8369118943a1_initial_revision.py`. This is the INITIAL revision, so your database is likely at a much later revision.

**Steps:**
1. List all migration files in order:
```bash
docker exec <ctfd-container> ls /opt/CTFd/migrations/versions/*.py | sort
```

2. Find the last one and get its revision:
```bash
docker exec <ctfd-container> grep "^revision" /opt/CTFd/migrations/versions/<last-file>.py
```

3. Insert that revision:
```sql
INSERT INTO alembic_version (version_num) VALUES ('<revision-from-last-file>');
```

### Step 8: Restart CTFd

```bash
docker restart <ctfd-container>
# OR
docker-compose restart ctfd
```

## Alternative: Use Alembic Stamp (Recommended if Available)

If you have access to run Alembic commands, the easiest solution is:

```bash
# Connect to the CTFd container
docker exec -it <ctfd-container> bash

# Navigate to CTFd directory
cd /opt/CTFd

# Stamp the database to the latest revision (without running migrations)
alembic stamp head

# OR stamp to a specific revision if you know it
alembic stamp <revision-number>
```

This tells Alembic "the database is already at this version" without actually running migrations.

## Finding the Latest Revision - Python Script

If you want to programmatically find it, you can create a quick script:

```python
# find_latest_revision.py
import os
import re

migrations_dir = "/opt/CTFd/migrations/versions"
files = sorted(os.listdir(migrations_dir))

latest_file = None
latest_revision = None

for file in files:
    if file.endswith('.py'):
        with open(os.path.join(migrations_dir, file), 'r') as f:
            content = f.read()
            match = re.search(r'^revision\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
            if match:
                revision = match.group(1)
                if latest_file is None or file > latest_file:
                    latest_file = file
                    latest_revision = revision

print(f"Latest migration: {latest_file}")
print(f"Latest revision: {latest_revision}")
```

Run it:
```bash
docker exec <ctfd-container> python /path/to/find_latest_revision.py
```

## Important Notes

- **Backup your database first!**
- The `alembic_version` table should have exactly ONE row with the latest revision
- After fixing the main CTFd version, you'll still need to handle plugin versions separately
- If you're unsure, it's safer to use `alembic stamp head` if available

