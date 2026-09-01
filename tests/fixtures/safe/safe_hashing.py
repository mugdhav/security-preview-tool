"""Must-NOT-detect: bcrypt for password storage."""
import bcrypt


def store(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
