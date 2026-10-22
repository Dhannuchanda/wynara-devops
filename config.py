"""
Configuration for the application
"""
import os

class Config:
    """Application configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = './flask_session'
    SESSION_PERMANENT = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

config = Config()
