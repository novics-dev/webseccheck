#!/usr/bin/env python3
"""Initialize the WebSecCheck database."""
from dotenv import load_dotenv

load_dotenv()

from app import create_app, db

app = create_app()
with app.app_context():
    db.create_all()
    print('Database initialized successfully.')
    print(f'Database: {app.config.get("SQLALCHEMY_DATABASE_URI", "").split("///")[-1]}')
