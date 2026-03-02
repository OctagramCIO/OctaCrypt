import os

def generate_symmetric_key(length=32):
    return os.urandom(length)