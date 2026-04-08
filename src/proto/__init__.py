import sys
import os

# bikin folder proto jadi root untuk import internal gRPC
sys.path.insert(0, os.path.dirname(__file__))