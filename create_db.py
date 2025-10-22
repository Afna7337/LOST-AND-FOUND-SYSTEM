from app import db, app

with app.app_context():
    db.create_all()  # This will create all tables based on your SQLAlchemy models

print("Database and tables created successfully!")
