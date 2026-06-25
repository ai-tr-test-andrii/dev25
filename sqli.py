import sqlite3

def get_user_vulnerable(username: str):
    """
    VULNERABLE: directly interpolates user input into the SQL string.
    An attacker can pass:  ' OR '1'='1  --  to dump the whole table.
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ Never do this — input is spliced directly into the query string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    print(f"[DEBUG] Executing: {query}")

    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results


if __name__ == "__main__":
    # Normal use
    print(get_user_vulnerable("alice"))

    # SQL injection attack — returns every row in the table
    print(get_user_vulnerable("' OR '1'='1"))

    # Drops the entire table (comment syntax varies by DB engine)
    print(get_user_vulnerable("'; DROP TABLE users; --"))
