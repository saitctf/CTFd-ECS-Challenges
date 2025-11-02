# Fix Alembic Version Error

If you're getting the error `ResolutionError: No such revision or branch 'a1b2c3d4e5f6'`, the database has a record of a migration that no longer exists.

## Quick Fix

Run this script on your CTFd server to fix the Alembic version tracking:

```bash
# Copy the script to your CTFd container
docker cp fix_alembic_version.py ctfd-ctfd-1:/opt/CTFd/

# Run it
docker exec ctfd-ctfd-1 python /opt/CTFd/fix_alembic_version.py
```

Or if you have direct database access:

```bash
python fix_alembic_version.py
```

## Manual SQL Fix

If the script doesn't work, you can manually update the database:

```sql
UPDATE alembic_version 
SET version_num = '8fb71d82c1e7' 
WHERE version_num = 'a1b2c3d4e5f6';
```

## What This Does

The script updates the Alembic version table to point to the correct latest revision (`8fb71d82c1e7`) instead of the non-existent one (`a1b2c3d4e5f6`). Since the `timeout` column already exists (added by the Pulumi script), this just fixes the version tracking so CTFd can start properly.

