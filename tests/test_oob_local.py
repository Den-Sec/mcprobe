import httpx
from mcprobe.oob.local import LocalOOB


def test_local_oob_captures_callback():
    with LocalOOB() as oob:
        token, url = oob.new_token()
        assert token in url
        httpx.get(url, timeout=5)
        hits = oob.interactions(token)
        assert len(hits) >= 1
        assert oob.interactions("other-token") == []


def test_local_oob_poll_all_returns_all_interactions():
    import httpx
    from mcprobe.oob.local import LocalOOB
    with LocalOOB() as oob:
        t1, u1 = oob.new_token()
        t2, u2 = oob.new_token()
        httpx.get(u1, timeout=5)
        httpx.get(u2, timeout=5)
        allhits = oob.poll_all()
        assert t1 in allhits and t2 in allhits
        assert allhits[t1] and allhits[t2]
