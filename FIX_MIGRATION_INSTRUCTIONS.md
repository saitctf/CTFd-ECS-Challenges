# Fix for Migration Error: Duplicate Column 'timeout'

## Problem
After running `docker-compose build --no-cache`, CTFd is failing to start with the error:
```
sqlalchemy.exc.OperationalError: (pymysql.err.OperationalError) (1060, "Duplicate column name 'timeout'")
```

This occurs because migration `113uj5m91yf2` is trying to add a `timeout` column to the `ecs_challenge` table, but the column already exists in your database.

## Solution Applied
The migration file `ecs_challenges/migrations/113uj5m91yf2_.py` has been updated to check if the `timeout` column exists before attempting to add it. This makes the migration idempotent and safe to run multiple times.

## What Was Changed
- Modified `upgrade()` function to check for column existence before adding
- Modified `downgrade()` function to check for column existence before dropping
- Uses `information_schema` to safely check column existence

## Next Steps

### Option 1: Rebuild and Restart (Recommended)
Since the migration file has been fixed, you can now rebuild and restart:

```bash
cd /Users/garretdonaldson/Documents/Projects/CTFd-ECS-Challenges
docker-compose build --no-cache
docker-compose up -d
```

The migration should now run successfully without errors.

### Option 2: Manual Database Fix (If Option 1 doesn't work)
If you still encounter issues, you can manually verify and fix the database state:

1. **Connect to your MySQL database:**
   ```bash
   # If using docker-compose
   docker-compose exec db mysql -u root -p ctfd
   
   # Or connect directly to RDS
   mysql -h ctfd-db2647bab.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u <username> -p ctfd
   ```

2. **Verify the timeout column exists:**
   ```sql
   DESCRIBE ecs_challenge;
   ```
   You should see the `timeout` column listed.

3. **Check migration version tracking:**
   ```sql
   -- Check what version tables exist
   SHOW TABLES LIKE '%version%';
   
   -- Check plugin-specific version table (if it exists)
   SELECT * FROM alembic_version_ecs_challenges;
   ```

4. **If needed, manually mark migration as complete:**
   ```sql
   -- This depends on how CTFd tracks plugin migrations
   -- You may need to insert into a plugin-specific version table
   -- Check the CTFd documentation or source code for the exact table name
   ```

### Option 3: Verify Column Exists (Quick Check)
Run the SQL script provided:
```bash
mysql -h <your-db-host> -u <username> -p ctfd < fix_migration_timeout.sql
```

## Verification
After applying the fix, verify CTFd starts successfully:
```bash
docker-compose logs -f ctfd
```

You should see the application start without migration errors.

## Files Modified
- `ecs_challenges/migrations/113uj5m91yf2_.py` - Updated to check column existence

## Files Created
- `fix_migration_timeout.sql` - SQL script for manual verification/fix
- `FIX_MIGRATION_INSTRUCTIONS.md` - This file

## Notes
- The migration is now idempotent and can be run multiple times safely
- The column check uses `information_schema`, which is standard across MySQL versions
- If you continue to have issues, check the CTFd logs for more specific error messages

