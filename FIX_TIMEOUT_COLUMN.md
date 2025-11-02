# Fix Missing `timeout` Column in `ecs_challenge` Table

## Problem
CTFd is trying to create/update an ECS challenge but getting:
```
pymysql.err.OperationalError: (1054, "Unknown column 'timeout' in 'field list'")
```

The `ecs_challenge` table is missing the `timeout` column that the plugin code expects.

## Solution

### Option 1: Quick SQL Fix (Recommended)

Connect to your database and run:

```sql
USE ctfd;
ALTER TABLE ecs_challenge ADD COLUMN timeout INT NULL;
```

This adds the column immediately without needing to restart anything.

### Option 2: Run Alembic Migration

If you want to use the migration system:

1. **SSH into your EC2 instance:**
```bash
ssh -i <key> ubuntu@<ec2-ip>
```

2. **Get into the CTFd container:**
```bash
docker exec -it <ctfd-container> bash
```

3. **Run the migration:**
```bash
cd /opt/CTFd
alembic -x plugin_name=ecs_challenges upgrade head
```

4. **Or if that doesn't work, run directly with Python:**
```python
from CTFd import create_app
from CTFd.models import db
from alembic import context
from alembic.config import Config

app = create_app()
with app.app_context():
    # Run the migration
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", "/opt/CTFd/CTFd/plugins/ecs_challenges/migrations")
    with context.begin_transaction():
        context.run_migrations(direction="upgrade", revision="head")
```

### Option 3: Direct Database Connection

If you have direct MySQL access:

```bash
mysql -h ctfd-db2647bab.cr8mkqkqcf0i.us-west-1.rds.amazonaws.com -u ctfd_admin -p ctfd
```

Then:
```sql
ALTER TABLE ecs_challenge ADD COLUMN timeout INT NULL;
```

## Verify the Fix

After adding the column, verify it exists:

```sql
DESCRIBE ecs_challenge;
```

You should see the `timeout` column listed.

Then try creating a challenge again in the CTFd admin panel.

## Migration File Created

A migration file has been created at:
`ecs_challenges/migrations/113uj5m91yf2_.py`

This will be automatically applied the next time the plugin migrations run, or you can apply it manually as shown above.

