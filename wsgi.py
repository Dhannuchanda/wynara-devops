"""
WSGI entry point for production deployment (Gunicorn)
"""
import os
from app import app

if __name__ == "__main__":
    app.run()
