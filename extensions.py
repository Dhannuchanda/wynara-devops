"""
Flask extensions - initialized here to avoid circular imports
"""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Rate limiter instance - will be initialized with app in app.py
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=["200 per day", "50 per hour"]
)

# Rate limit constants for sensitive endpoints
AUTH_LIMIT = "5 per minute"
REGISTER_LIMIT = "3 per minute" 
OTP_LIMIT = "5 per minute"
