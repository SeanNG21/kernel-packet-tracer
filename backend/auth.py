"""
Authentication utilities for NFT Tracer
"""
from functools import wraps
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from models import User, db


def init_default_user():
    root = User.query.filter_by(username='root').first()
    if not root:
        try:
            root = User(
                username='root',
                email='root@localhost',
                first_login=True
            )
            root.set_password('root')
            db.session.add(root)
            db.session.commit()
            print("[✓] Default root user created (username: root, password: root)")
            return root, True
        except Exception as e:
            db.session.rollback()
            print(f"[!] Error creating root user: {e}")
            return None, False
    return root, False


def authenticate_user(username: str, password: str) -> tuple:
    user = User.query.filter_by(username=username).first()

    if not user:
        return None, "Invalid username or password"

    if not user.is_active:
        return None, "User account is inactive"

    if not user.check_password(password):
        return None, "Invalid username or password"

    # Update last login
    try:
        user.last_login = datetime.utcnow()
        db.session.commit()
    except:
        db.session.rollback()

    return user, None


def create_tokens(user_id: int) -> dict:
    access_token = create_access_token(
        identity=user_id,
        expires_delta=timedelta(hours=24)
    )
    refresh_token = create_refresh_token(
        identity=user_id,
        expires_delta=timedelta(days=30)
    )

    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer',
        'expires_in': 86400  # 24 hours in seconds
    }


def token_required(fn):
    """
    Decorator to require JWT token for route
    """
    @wraps(fn)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401

        # Add user to kwargs
        return fn(*args, user=user, **kwargs)

    return decorated_function


def optional_token(fn):
    @wraps(fn)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        user = None

        if auth_header.startswith('Bearer '):
            try:
                from flask_jwt_extended import verify_jwt_in_request
                verify_jwt_in_request()
                current_user_id = get_jwt_identity()
                user = User.query.get(current_user_id)
            except:
                pass  # Token is invalid or missing, continue as anonymous

        return fn(*args, user=user, **kwargs)

    return decorated_function


def change_password(user_id: int, old_password: str, new_password: str) -> tuple:
    user = User.query.get(user_id)

    if not user:
        return False, "User not found"

    if not user.check_password(old_password):
        return False, "Incorrect old password"

    if len(new_password) < 6:
        return False, "New password must be at least 6 characters"

    if old_password == new_password:
        return False, "New password must be different from old password"

    try:
        user.set_password(new_password)
        user.first_login = False
        db.session.commit()
        return True, None
    except Exception as e:
        db.session.rollback()
        return False, f"Database error: {str(e)}"