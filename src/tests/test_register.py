import base64

import srp
from srp import create_salted_verification_key

from src.routes.models.register import RegisterOutput
from src.tests.conftest import client, override_get_session


def test_register_success_returns_register_output(client, override_get_session):
    username = "register_ok_user"
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
    out = RegisterOutput.model_validate(r.json())
    assert out.user_id >= 1
    assert out.access_token


def test_register_duplicate_returns_400(client, override_get_session):
    username = "register_dup_user"
    password = "secret"
    salt, verifier = create_salted_verification_key(
        username, password, hash_alg=srp.SHA1, ng_type=srp.NG_2048
    )
    body = {
        "username": username,
        "salt": base64.b64encode(salt).decode(),
        "verifier": base64.b64encode(verifier).decode(),
    }
    r1 = client.post("/register", json=body)
    assert r1.status_code == 201
    r2 = client.post("/register", json=body)
    assert r2.status_code == 400
    assert r2.json()["detail"] == "Registration could not be completed"
