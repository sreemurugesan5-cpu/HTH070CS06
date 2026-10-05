import os
import sys

# Ensure repository root is in Python sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.app import app

# Expose WSGI application for Vercel serverless functions
if __name__ == '__main__':
    app.run()
