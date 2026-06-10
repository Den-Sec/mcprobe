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
