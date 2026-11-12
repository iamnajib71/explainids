from ids.auth import LoginLimiter, hash_password, issue_token, parse_users, read_token, verify_password

SECRET = b"s" * 32


def test_password_hash_verifies_and_is_salted():
    h = hash_password("correct horse battery", iterations=1000)
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    assert h != hash_password("correct horse battery", iterations=1000)
    assert not verify_password("x", "garbage") and not verify_password("x", "md5$1$a$b")


def test_parse_users_ignores_malformed_entries():
    h = hash_password("pw", iterations=1000)
    assert parse_users(f"alice:{h}, bob:plain ,:{h},carol") == {"alice": h}
    assert parse_users(None) == {}


def test_session_token_rejects_forgery_and_expiry():
    t = issue_token("alice", SECRET, now=1000, ttl=60)
    assert read_token(t, SECRET, now=1010) == "alice"
    assert read_token(t, SECRET, now=1061) is None
    assert read_token(t, b"other" * 8, now=1010) is None
    body, sig = t.rsplit(".", 1)
    forged = issue_token("mallory", b"guess" * 8, now=1000, ttl=60).rsplit(".", 1)[0] + "." + sig
    assert read_token(forged, SECRET, now=1010) is None
    assert read_token(None, SECRET) is None and read_token("nodot", SECRET) is None


def test_login_limiter_blocks_after_limit_within_window():
    lim = LoginLimiter(limit=3, window=100)
    for t in range(3):
        assert not lim.blocked("ip", now=t)
        lim.fail("ip", now=t)
    assert lim.blocked("ip", now=5) and not lim.blocked("other", now=5)
    assert not lim.blocked("ip", now=200)
    lim.fail("ip", now=200); lim.clear("ip")
    assert not lim.blocked("ip", now=201)
