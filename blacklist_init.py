"""
Initialize common blacklisted domains in the database
Run this script once to populate default blacklisted domains
"""
from models import db, BlacklistedDomain, User
from domain_utils import add_common_blacklist_domains

def initialize_common_blacklisted_domains():
    """Add common social media and marketplace domains to blacklist"""
    
    # Get admin user (assuming first admin user exists)
    admin_user = User.query.filter_by(role='ADMIN').first()
    if not admin_user:
        print("❌ No admin user found. Please create an admin user first.")
        return False
    
    common_domains = add_common_blacklist_domains()
    added_count = 0
    
    for domain in common_domains:
        # Check if domain already exists
        existing = BlacklistedDomain.query.filter_by(domain=domain).first()
        if not existing:
            blacklisted_domain = BlacklistedDomain(
                domain=domain,
                reason="Common social media/marketplace domain - not business focused",
                added_by=admin_user.id,
                is_active=True
            )
            db.session.add(blacklisted_domain)
            added_count += 1
    
    try:
        db.session.commit()
        print(f"✅ Successfully added {added_count} blacklisted domains")
        print(f"📊 Total blacklisted domains: {BlacklistedDomain.query.count()}")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error adding blacklisted domains: {str(e)}")
        return False

if __name__ == "__main__":
    initialize_common_blacklisted_domains()