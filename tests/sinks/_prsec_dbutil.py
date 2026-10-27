from psycopg.types.json import Jsonb


def insert_scan(pool, repo="acme/shop", pr=7, head_sha="a" * 40, **kw) -> int:
    cols = {"repo": repo, "pr": pr, "head_sha": head_sha, "skills_version": "dev", **kw}
    names = ", ".join(cols)
    ph = ", ".join(["%s"] * len(cols))
    with pool.connection() as c:
        return c.execute(f"INSERT INTO scans ({names}) VALUES ({ph}) RETURNING id", list(cols.values())).fetchone()[0]


def jsonb(v):
    return Jsonb(v)
