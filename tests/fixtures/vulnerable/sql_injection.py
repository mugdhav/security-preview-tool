"""Must-detect: SQL built by string interpolation and by multi-line concat."""


def get_user(db, uid):
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return cur.fetchone()


def search(db, term):
    query = ("SELECT name FROM products WHERE title LIKE '%"
             + term + "%'")
    db.cursor().execute(query)
