import pytest
from flask import Flask
from unittest.mock import patch, MagicMock
import jwt as pyjwt
from server.utils import jwt as jwt_utils
from server.utils.jwt import JWTError

CODE_OK = 200
CODE_UNAUTHORIZED = 401
CODE_BAD_REQUEST = 400
CODE_NOT_FOUND = 404
CODE_ERROR = 500

def make_token(payload, secret, alg='HS256'):
    return pyjwt.encode(payload, secret, algorithm=alg)

@pytest.fixture(scope="module")
def app_fixture():
    app = Flask(__name__)
    app.config.update(TESTING=True, JWT_SECRET_KEY="testsecret")
    return app

@pytest.fixture(autouse=True)
def app_ctx(app_fixture):
    with app_fixture.app_context():
        yield

@pytest.mark.parametrize("header, token_payload, decode_error, expected_status, expected_error", [
    (None, None, None, CODE_UNAUTHORIZED, "Missing or malformed token"),
    ("Bearer badtoken", None, "Invalid token", CODE_UNAUTHORIZED, "Invalid token"),
    ("Bearer validtoken", {"user_id": 1, "iat": 1, "type": "access"}, None, None, None),
])
def test_get_current_token(header, token_payload, decode_error, expected_status, expected_error, app_ctx, mocker):
    mock_request = MagicMock()
    mock_request.headers.get.return_value = header
    mocker.patch("server.utils.jwt.request", mock_request)
    if token_payload:
        mocker.patch("server.utils.jwt.decode_token", return_value=token_payload)
    elif decode_error:
        mocker.patch("server.utils.jwt.decode_token", side_effect=JWTError(decode_error, expected_status))
    if expected_status:
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.get_current_token()
        assert excinfo.value.status == expected_status
        assert expected_error in str(excinfo.value)
    else:
        token = jwt_utils.get_current_token()
        assert token == "validtoken"

@pytest.mark.parametrize("token, decode_result, expected_user_id, expected_status, expected_error", [
    ("goodtoken", {"user_id": 42, "type": "access"}, 42, None, None),
    ("badtoken", JWTError("Invalid token", CODE_UNAUTHORIZED), None, CODE_UNAUTHORIZED, "Invalid token"),
])
def test_get_user_id_from_token(token, decode_result, expected_user_id, expected_status, expected_error, app_ctx, mocker):
    if isinstance(decode_result, Exception):
        mocker.patch("server.utils.jwt.decode_token", side_effect=decode_result)
    else:
        mocker.patch("server.utils.jwt.decode_token", return_value=decode_result)
    if expected_status:
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.get_user_id_from_token(token)
        assert excinfo.value.status == expected_status
        assert expected_error in str(excinfo.value)
    else:
        user_id = jwt_utils.get_user_id_from_token(token)
        assert user_id == expected_user_id

@pytest.mark.parametrize("payload, db_invalid, token_type, exp_error, exp_status", [
    ("validtoken", False, "access", None, None),
    ("expiredtoken", False, "access", "Token has expired", CODE_UNAUTHORIZED),
    ("invalidtoken", False, "access", "Invalid token", CODE_UNAUTHORIZED),
    ("validtoken", True, "access", "Token has been invalidated", CODE_UNAUTHORIZED),
    ("validtoken", False, "refresh", "Invalid token type", CODE_UNAUTHORIZED),
])
def test_decode_token(payload, db_invalid, token_type, exp_error, exp_status, app_ctx, mocker):
    secret = "testsecret"
    from datetime import datetime, timezone
    if exp_error == "Token has expired":
        mocker.patch("jwt.decode", side_effect=pyjwt.ExpiredSignatureError)
    elif exp_error == "Invalid token":
        mocker.patch("jwt.decode", side_effect=pyjwt.InvalidTokenError)
    else:
        mock_payload = {"user_id": 1, "iat": 1, "type": token_type}
        mocker.patch("jwt.decode", return_value=mock_payload)
        if db_invalid:
            mock_db = MagicMock()
            mock_db.query().filter_by().first.return_value = MagicMock(earliest_valid_iat=datetime(2000, 1, 2, tzinfo=timezone.utc))
            mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
        else:
            mock_db = MagicMock()
            mock_db.query().filter_by().first.return_value = None
            mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
    if exp_error:
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.decode_token(payload)
        assert excinfo.value.status == exp_status
        assert exp_error in str(excinfo.value)
    else:
        result = jwt_utils.decode_token(payload)
        assert result["user_id"] == 1
        assert result["type"] == token_type

@pytest.mark.parametrize("token_type, db_invalid, exp_error, exp_status", [
    ("refresh", False, None, None),
    ("access", False, "Invalid token type", CODE_UNAUTHORIZED),
    ("refresh", True, "Token has been invalidated", CODE_UNAUTHORIZED),
    ("refresh", False, "Token has expired", CODE_UNAUTHORIZED),
    ("refresh", False, "Invalid token", CODE_UNAUTHORIZED),
])
def test_refresh_access_token(token_type, db_invalid, exp_error, exp_status, app_ctx, mocker):
    secret = "testsecret"
    from datetime import datetime, timezone
    if exp_error == "Token has expired":
        mocker.patch("jwt.decode", side_effect=pyjwt.ExpiredSignatureError)
    elif exp_error == "Invalid token":
        mocker.patch("jwt.decode", side_effect=pyjwt.InvalidTokenError)
    else:
        mock_payload = {"user_id": 1, "iat": 1, "type": token_type}
        mocker.patch("jwt.decode", return_value=mock_payload)
        if db_invalid:
            mock_db = MagicMock()
            mock_db.query().filter_by().first.return_value = MagicMock(earliest_valid_iat=datetime(2000, 1, 2, tzinfo=timezone.utc))
            mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
        else:
            mock_db = MagicMock()
            mock_db.query().filter_by().first.return_value = None
            mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
    if not exp_error:
        mocker.patch("server.utils.jwt.generate_token", return_value=("newaccesstoken", "refresh"))
    token = "refreshtoken"
    if exp_error:
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.refresh_access_token(token)
        assert excinfo.value.status == exp_status
        assert exp_error in str(excinfo.value)
    else:
        val = jwt_utils.refresh_access_token(token)
        assert val == "newaccesstoken"

@pytest.mark.parametrize("decode_side_effect, db_exists, exp_result", [
    (None, True, True),
    (None, False, True),
    (Exception, True, False),
])
def test_invalidate_token(decode_side_effect, db_exists, exp_result, app_ctx, mocker):
    secret = "testsecret"
    if decode_side_effect:
        mocker.patch("jwt.decode", side_effect=decode_side_effect)
    else:
        mocker.patch("jwt.decode", return_value={"user_id": 1, "iat": 1})
    mock_db = MagicMock()
    if db_exists:
        mock_db.query().filter_by().first.return_value = MagicMock()
    else:
        mock_db.query().filter_by().first.return_value = None
    mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
    result = jwt_utils.invalidate_token("sometoken")
    assert result is exp_result

def test_cleanup_expired_invalidations(app_ctx, mocker):
    mock_db = MagicMock()
    mock_db.query().all.return_value = [MagicMock(earliest_valid_iat=1)]
    mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
    mocker.patch("server.utils.jwt.config.jwt.access_token_expires", 1)
    mocker.patch("server.utils.jwt.config.jwt.refresh_token_expires", 1)
    mocker.patch("server.utils.jwt.datetime", MagicMock(now=lambda *a, **kw: 100))
    jwt_utils.cleanup_expired_invalidations()
    assert mock_db.delete.called
    assert mock_db.commit.called
