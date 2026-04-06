"""KeySentry — SSH Key Auditor & Expiry Tracker. Run: python run.py [OPTIONS]"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from keysentry.cli import main
if __name__ == "__main__":
    sys.exit(main())
