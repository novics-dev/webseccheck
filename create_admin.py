#!/usr/bin/env python3
"""Create or update a WebSecCheck admin user."""
import argparse
import getpass
import sys
from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(description='Create WebSecCheck admin user')
    parser.add_argument('--email', help='Admin email address')
    parser.add_argument('--password', help='Admin password (use interactive prompt instead)')
    args = parser.parse_args()

    from app import create_app, db
    from app.models.models import User

    app = create_app()
    with app.app_context():
        email = args.email
        if not email:
            email = input('Admin email: ').strip()
        if not email or '@' not in email:
            print('Valid email address required.')
            sys.exit(1)

        existing = User.query.filter_by(email=email).first()

        if existing:
            print(f'User {email} already exists.')
            update = input('Update password? [y/N]: ').strip().lower()
            if update != 'y':
                sys.exit(0)
            password = _get_password(args.password)
            existing.set_password(password)
            db.session.commit()
            print(f'Password updated for {email}.')
        else:
            password = _get_password(args.password)
            user = User(email=email, is_admin=True)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f'Admin user created: {email}')


def _get_password(cli_password=None):
    if cli_password:
        _validate_password(cli_password)
        return cli_password
    while True:
        password = getpass.getpass('Password: ')
        confirm = getpass.getpass('Confirm password: ')
        if password != confirm:
            print('Passwords do not match. Try again.')
            continue
        try:
            _validate_password(password)
            return password
        except ValueError as e:
            print(str(e))


def _validate_password(password):
    if len(password) < 12:
        raise ValueError('Password must be at least 12 characters.')
    if password.isdigit() or password.isalpha():
        raise ValueError('Password must contain both letters and numbers.')


if __name__ == '__main__':
    main()
