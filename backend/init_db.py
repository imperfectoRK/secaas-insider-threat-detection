"""
SECaaS Insider Threat Detection - Database Initialization Script

This script initializes the PostgreSQL database with the schema and sample data.
Run this script after creating the database and tables.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.config import DATABASE_URL
from backend.models import Base, Role, User, RolePolicy, RoleBaseline, Alert

def init_database():
    """Initialize database with sample data."""
    # Create engine
    engine = create_engine(DATABASE_URL, echo=False)
    
    # Create tables
    Base.metadata.create_all(engine)
    
    # Create session
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Check if data already exists
        existing_roles = session.query(Role).count()
        if existing_roles > 0:
            print("Database already initialized with roles. Skipping...")
            session.close()
            return
        
        # Insert roles
        roles = [
            Role(role_name="admin", description="System administrator with full access"),
            Role(role_name="manager", description="Manager with elevated privileges"),
            Role(role_name="staff", description="Regular staff member")
        ]
        session.add_all(roles)
        session.flush()  # Get role IDs
        
        # Insert users
        admin_user = User(user_id="admin001", role_id=roles[0].role_id, status="active")
        manager_user = User(user_id="manager001", role_id=roles[1].role_id, status="active")
        staff_user = User(user_id="staff001", role_id=roles[2].role_id, status="active")
        staff_user2 = User(user_id="staff002", role_id=roles[2].role_id, status="active")
        session.add_all([admin_user, manager_user, staff_user, staff_user2])
        
        # Insert role policies (allowed actions per role)
        # Admin policies - full access
        admin_policies = [
            RolePolicy(role_id=roles[0].role_id, action="READ", resource="*"),
            RolePolicy(role_id=roles[0].role_id, action="WRITE", resource="*"),
            RolePolicy(role_id=roles[0].role_id, action="UPDATE", resource="*"),
            RolePolicy(role_id=roles[0].role_id, action="DELETE", resource="*"),
        ]
        
        # Manager policies - elevated but limited
        manager_policies = [
            RolePolicy(role_id=roles[1].role_id, action="READ", resource="Finance_Reports"),
            RolePolicy(role_id=roles[1].role_id, action="READ", resource="Employee_Records"),
            RolePolicy(role_id=roles[1].role_id, action="WRITE", resource="Finance_Reports"),
            RolePolicy(role_id=roles[1].role_id, action="UPDATE", resource="Finance_Reports"),
        ]
        
        # Staff policies - limited access
        staff_policies = [
            RolePolicy(role_id=roles[2].role_id, action="READ", resource="General_Documents"),
            RolePolicy(role_id=roles[2].role_id, action="READ", resource="Public_Reports"),
            RolePolicy(role_id=roles[2].role_id, action="WRITE", resource="Own_Work"),
        ]
        
        session.add_all(admin_policies + manager_policies + staff_policies)
        
        # Insert role baselines (normal behavioral patterns)
        baselines = [
            RoleBaseline(
                role_id=roles[0].role_id,
                avg_records_per_access=100.0,
                avg_access_per_day=50,
                normal_start_hour=0,
                normal_end_hour=23  # Admins have 24/7 access
            ),
            RoleBaseline(
                role_id=roles[1].role_id,
                avg_records_per_access=50.0,
                avg_access_per_day=30,
                normal_start_hour=7,
                normal_end_hour=19  # Managers: 7 AM - 7 PM
            ),
            RoleBaseline(
                role_id=roles[2].role_id,
                avg_records_per_access=5.0,
                avg_access_per_day=20,
                normal_start_hour=9,
                normal_end_hour=17  # Staff: 9 AM - 5 PM
            ),
        ]
        session.add_all(baselines)
        
        # Commit changes
        session.commit()
        print("Database initialized successfully!")
        print(f"Created {len(roles)} roles")
        print(f"Created {len([admin_user, manager_user, staff_user, staff_user2])} users")
        print(f"Created {len(admin_policies + manager_policies + staff_policies)} policies")
        print(f"Created {len(baselines)} baselines")
        
    except Exception as e:
        session.rollback()
        print(f"Error initializing database: {e}")
        raise
    finally:
        session.close()

if __name__ == "__main__":
    init_database()

