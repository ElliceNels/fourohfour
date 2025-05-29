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

# Test: get_current_token should raise JWTError for missing/malformed/invalid tokens, or return token string for valid tokens
@pytest.mark.parametrize("header, token_payload, decode_error, expected_status, expected_error", [
    (None, None, None, CODE_UNAUTHORIZED, "Missing or malformed token"),
    ("Bearer badtoken", None, "Invalid token", CODE_UNAUTHORIZED, "Invalid token"),
    ("Bearer validtoken", {"user_id": 1, "iat": 1, "type": "access"}, None, None, None),
])
def test_get_current_token(header, token_payload, decode_error, expected_status, expected_error, app_ctx, mocker):
    """
    Test extraction and validation of JWT from the Authorization header.
    - Should raise JWTError for missing/malformed/invalid tokens.
    - Should return the token string for valid tokens.
    """
    # Mock the request header and decode_token behavior
    mock_request = MagicMock()
    mock_request.headers.get.return_value = header
    mocker.patch("server.utils.jwt.request", mock_request)
    if token_payload:
        mocker.patch("server.utils.jwt.decode_token", return_value=token_payload)
    elif decode_error:
        mocker.patch("server.utils.jwt.decode_token", side_effect=JWTError(decode_error, expected_status))
    if expected_status:
        # Should raise JWTError for error cases
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.get_current_token()
        assert excinfo.value.status == expected_status
        assert expected_error in str(excinfo.value)
    else:
        # Should return the token string for valid case
        token = jwt_utils.get_current_token()
        assert token == "validtoken"

# Test: get_user_id_from_token should raise JWTError for invalid tokens, or return user_id for valid tokens
@pytest.mark.parametrize("token, decode_result, expected_user_id, expected_status, expected_error", [
    ("goodtoken", {"user_id": 42, "type": "access"}, 42, None, None),
    ("badtoken", JWTError("Invalid token", CODE_UNAUTHORIZED), None, CODE_UNAUTHORIZED, "Invalid token"),
])
def test_get_user_id_from_token(token, decode_result, expected_user_id, expected_status, expected_error, app_ctx, mocker):
    """
    Test extraction of user_id from a JWT.
    - Should raise JWTError for invalid tokens.
    - Should return user_id for valid tokens.
    """
    # Mock decode_token behavior
    if isinstance(decode_result, Exception):
        mocker.patch("server.utils.jwt.decode_token", side_effect=decode_result)
    else:
        mocker.patch("server.utils.jwt.decode_token", return_value=decode_result)
    if expected_status:
        # Should raise JWTError for error cases
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.get_user_id_from_token(token)
        assert excinfo.value.status == expected_status
        assert expected_error in str(excinfo.value)
    else:
        # Should return user_id for valid case
        user_id = jwt_utils.get_user_id_from_token(token)
        assert user_id == expected_user_id

# Test: decode_token should handle all JWT validation and DB invalidation logic
@pytest.mark.parametrize("payload, db_invalid, token_type, exp_error, exp_status", [
    ("validtoken", False, "access", None, None),
    ("expiredtoken", False, "access", "Token has expired", CODE_UNAUTHORIZED),
    ("invalidtoken", False, "access", "Invalid token", CODE_UNAUTHORIZED),
    ("validtoken", True, "access", "Token has been invalidated", CODE_UNAUTHORIZED),
    ("validtoken", False, "refresh", "Invalid token type", CODE_UNAUTHORIZED),
])
def test_decode_token(payload, db_invalid, token_type, exp_error, exp_status, app_ctx, mocker):
    """
    Test decoding and validation of JWT payloads, including DB invalidation and token type checks.
    - Should raise JWTError for expired, invalid, or invalidated tokens, or wrong token type.
    - Should return payload for valid tokens.
    """
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
        # Should raise JWTError for error cases
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.decode_token(payload)
        assert excinfo.value.status == exp_status
        assert exp_error in str(excinfo.value)
    else:
        # Should return payload for valid case
        result = jwt_utils.decode_token(payload)
        assert result["user_id"] == 1
        assert result["type"] == token_type

# Test: refresh_access_token should only allow valid refresh tokens and not invalidated/expired/invalid ones
@pytest.mark.parametrize("token_type, db_invalid, exp_error, exp_status", [
    ("refresh", False, None, None),
    ("access", False, "Invalid token type", CODE_UNAUTHORIZED),
    ("refresh", True, "Token has been invalidated", CODE_UNAUTHORIZED),
    ("refresh", False, "Token has expired", CODE_UNAUTHORIZED),
    ("refresh", False, "Invalid token", CODE_UNAUTHORIZED),
])
def test_refresh_access_token(token_type, db_invalid, exp_error, exp_status, app_ctx, mocker):
    """
    Test refresh_access_token logic for refresh/access tokens and DB invalidation.
    - Should raise JWTError for invalid/expired/invalidated/wrong-type tokens.
    - Should return new access token for valid refresh tokens.
    """
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
        # Should raise JWTError for error cases
        with pytest.raises(JWTError) as excinfo:
            jwt_utils.refresh_access_token(token)
        assert excinfo.value.status == exp_status
        assert exp_error in str(excinfo.value)
    else:
        # Should return new access token for valid refresh token
        val = jwt_utils.refresh_access_token(token)
        assert val == "newaccesstoken"

# Test: invalidate_token should mark tokens as invalidated in DB, or return False if decode fails
@pytest.mark.parametrize("decode_side_effect, db_exists, exp_result", [
    (None, True, True),
    (None, False, True),
    (Exception, True, False),
])
def test_invalidate_token(decode_side_effect, db_exists, exp_result, app_ctx, mocker):
    """
    Test token invalidation logic.
    - Should return False if decode fails.
    - Should return True if DB invalidation logic succeeds (regardless of DB existence).
    """
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

# Test: cleanup_expired_invalidations should remove expired invalidation records from DB

def test_cleanup_expired_invalidations(app_ctx, mocker):
    """
    Test cleanup of expired invalidation records in the DB.
    - Should call delete and commit on the DB session for expired records.
    """
    mock_db = MagicMock()
    mock_db.query().all.return_value = [MagicMock(earliest_valid_iat=1)]
    mocker.patch("server.utils.jwt.get_session", return_value=MagicMock(__enter__=lambda s: mock_db, __exit__=lambda s,a,b,c: None))
    mocker.patch("server.utils.jwt.config.jwt.access_token_expires", 1)
    mocker.patch("server.utils.jwt.config.jwt.refresh_token_expires", 1)
    mocker.patch("server.utils.jwt.datetime", MagicMock(now=lambda *a, **kw: 100))
    jwt_utils.cleanup_expired_invalidations()
    assert mock_db.delete.called
    assert mock_db.commit.called
