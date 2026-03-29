import base64

import srp
from srp import User, create_salted_verification_key

from src.routes.models.register import RegisterOutput


def test_srp_register_and_login_flow(client, override_get_session):
    username = "alice_srp_test"
    password = "secret"
    salt, verifier = create_salted_verification_key(
        username, password, hash_alg=srp.SHA1, ng_type=srp.NG_2048
    )
    r = client.post(
        "/register",
        json={
            "username": username,
            "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(verifier).decode(),
        },
    )
    assert r.status_code == 201
    reg = RegisterOutput.model_validate(r.json())
    assert reg.user_id >= 1
    assert reg.access_token

    usr = User(username, password, hash_alg=srp.SHA1, ng_type=srp.NG_2048)
    _I, A = usr.start_authentication()
    r2 = client.post(
        "/srp/challenge",
        json={"username": username, "A": base64.b64encode(A).decode()},
    )
    assert r2.status_code == 200
    out = r2.json()
    session_id = out["session_id"]
    s = base64.b64decode(out["s"])
    B = base64.b64decode(out["B"])
    M = usr.process_challenge(s, B)
    assert M is not None
    r3 = client.post(
        "/srp/verify",
        json={
            "session_id": session_id,
            "username": username,
            "M": base64.b64encode(M).decode(),
        },
    )
    assert r3.status_code == 200
    body = r3.json()
    assert "HAMK" in body
    assert body["user_id"] >= 1
    assert body["access_token"]
    assert base64.b64decode(body["salt"]) == salt
