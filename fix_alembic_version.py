#!/usr/bin/env python3
"""
Fix Alembic version tracking for ECS Challenges plugin.
This script removes the reference to the non-existent revision 'a1b2c3d4e5f6'
and sets it back to the actual latest revision '8fb71d82c1e7'.

Run this script on your CTFd server:
    docker exec ctfd-ctfd-1 python /opt/CTFd/fix_alembic_version.py
    OR
    python fix_alembic_version.py (if run locally with database access)
"""
import os
import sys

try:
    # Try to use CTFd's database connection
    from CTFd import create_app
    from CTFd.models import db
    
    app = create_app()
    with app.app_context():
        from sqlalchemy import text
        
        # Check current version
        result = db.session.execute(text("SELECT version_num FROM alembic_version"))
        versions = [row[0] for row in result]
        print(f"Current Alembic versions in database: {versions}")
        
        # Check if the problematic revision exists
        if 'a1b2c3d4e5f6' in versions:
            print("Found problematic revision 'a1b2c3d4e5f6', fixing...")
            # Update to the correct latest revision
            db.session.execute(
                text("UPDATE alembic_version SET version_num = '8fb71d82c1e7' WHERE version_num = 'a1b2c3d4e5f6'")
            )
            db.session.commit()
            print("Successfully updated Alembic version to '8fb71d82c1e7'")
        elif '8fb71d82c1e7' in versions:
            print("Database already has correct revision '8fb71d82c1e7'")
        else:
            print("Warning: Neither problematic nor correct revision found in database")
            print("You may need to check the alembic_version table manually")
            
except ImportError:
    # Fallback: Direct database connection if CTFd isn't available
    import pymysql
    
    db_url = os.environ.get('DATABASE_URL', '')
    if not db_url:
        print("ERROR: DATABASE_URL environment variable not set")
        print("Please set it or run this script within the CTFd container")
        sys.exit(1)
    
    # Parse DATABASE_URL
    if 'mysql+pymysql://' not in db_url:
        print("ERROR: Only MySQL databases are supported")
        sys.exit(1)
    
    parts = db_url.replace('mysql+pymysql://', '').split('@')
    if len(parts) != 2:
        print("ERROR: Invalid DATABASE_URL format")
        sys.exit(1)
    
    user_pass = parts[0].split(':')
    if len(user_pass) != 2:
        print("ERROR: Invalid user:password format")
        sys.exit(1)
    
    host_db = parts[1].split('/')
    if len(host_db) != 2:
        print("ERROR: Invalid host/database format")
        sys.exit(1)
    
    user, password = user_pass[0], user_pass[1]
    host_port = host_db[0].split(':')
    host = host_port[0]
    port = int(host_port[1]) if len(host_port) > 1 else 3306
    database = host_db[1]
    
    print(f"Connecting to database: {host}:{port}, database: {database}")
    conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database, charset='utf8mb4')
    cursor = conn.cursor()
    
    # Check current versions
    cursor.execute("SELECT version_num FROM alembic_version")
    versions = [row[0] for row in cursor.fetchall()]
    print(f"Current Alembic versions in database: {versions}")
    
    # Fix if needed
    if 'a1b2c3d4e5f6' in versions:
        print("Found problematic revision 'a1b2c3d4e5f6', fixing...")
        cursor.execute("UPDATE alembic_version SET version_num = '8fb71d82c1e7' WHERE version_num = 'a1b2c3d4e5f6'")
        conn.commit()
        print("Successfully updated Alembic version to '8fb71d82c1e7'")
    elif '8fb71d82c1e7' in versions:
        print("Database already has correct revision '8fb71d82c1e7'")
    else:
        print("Warning: Neither problematic nor correct revision found in database")
        print("You may need to check the alembic_version table manually")
    
    cursor.close()
    conn.close()
    
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("Done!")

