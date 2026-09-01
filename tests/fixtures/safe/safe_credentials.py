"""Must-NOT-detect: secrets pulled from the environment."""
import os

db_password = os.environ["DB_PASSWORD"]
api_key = os.environ.get("API_KEY")
