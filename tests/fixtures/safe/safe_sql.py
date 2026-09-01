"""Must-NOT-detect: parameterised query."""


def get_user(db, uid):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cur.fetchone()
