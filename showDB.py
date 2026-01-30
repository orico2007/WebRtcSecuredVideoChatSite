import sqlite3

DB_PATH = "users.db"

def print_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT
            id,
            username,
            email,
            verified,
            verify_token,
            verify_sent_at
        FROM users
        ORDER BY id
    """)

    rows = c.fetchall()
    conn.close()

    if not rows:
        print("DB is empty.")
        return

    print("---- USERS TABLE ----")
    for r in rows:
        print(
            f"id={r[0]} | "
            f"username={r[1]} | "
            f"email={r[2]} | "
            f"verified={bool(r[3])} | "
            f"token={'YES' if r[4] else 'NO'} | "
            f"sent_at={r[5]}"
        )

if __name__ == "__main__":
    print_users()
