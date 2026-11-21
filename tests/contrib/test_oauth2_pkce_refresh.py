import base64
import hashlib
from urllib.parse import parse_qsl

import flask
import pytest
import responses
from flask import Flask
from urlobject import URLObject

from flask_dance.consumer.storage import MemoryStorage
from flask_dance.contrib.azure import make_azure_blueprint
from flask_dance.contrib.google import make_google_blueprint
from flask_dance.contrib.spotify import make_spotify_blueprint

PROVIDERS = [
    pytest.param(
        "google",
        make_google_blueprint,
        {"offline": True},
        "https://accounts.google.com/o/oauth2/token",
        "/userinfo",
        "https://www.googleapis.com/userinfo",
        id="google",
    ),
    pytest.param(
        "azure",
        make_azure_blueprint,
        {"scope": ["User.Read", "offline_access"]},
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "/v1.0/me",
        "https://graph.microsoft.com/v1.0/me",
        id="azure",
    ),
    pytest.param(
        "spotify",
        make_spotify_blueprint,
        {},
        "https://accounts.spotify.com/api/token",
        "/v1/me",
        "https://api.spotify.com/v1/me",
        id="spotify",
    ),
]


def make_provider_app(factory, provider_kwargs, storage):
    app = Flask(__name__)
    app.secret_key = "secret"
    app.config["SERVER_NAME"] = "a.b.c"
    blueprint = factory(
        client_id="client-id",
        client_secret="client-secret",
        redirect_to="index",
        storage=storage,
        use_pkce=True,
        **provider_kwargs,
    )
    app.register_blueprint(blueprint)

    @app.route("/")
    def index():
        return "index"

    return app, blueprint


@pytest.mark.parametrize(
    "provider,factory,provider_kwargs,token_url,api_path,api_url",
    PROVIDERS,
)
@responses.activate
def test_provider_pkce_authorization_flow(
    provider, factory, provider_kwargs, token_url, api_path, api_url
):
    storage = MemoryStorage()
    app, blueprint = make_provider_app(factory, provider_kwargs, storage)
    responses.add(
        responses.POST,
        token_url,
        json={
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "token_type": "bearer",
            "expires_in": 3600,
        },
    )

    with app.test_client() as client:
        response = client.get(
            f"/{provider}", base_url="https://a.b.c", follow_redirects=False
        )
        location = URLObject(response.headers["Location"])
        code_verifier = flask.session[f"{provider}_oauth_code_verifier"]
        expected_challenge = (
            base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )

        assert location.query_dict["code_challenge_method"] == "S256"
        assert location.query_dict["code_challenge"] == expected_challenge

        response = client.get(
            f"/{provider}/authorized",
            query_string={
                "code": "authorization-code",
                "state": location.query_dict["state"],
            },
            base_url="https://a.b.c",
        )

    assert response.status_code == 302
    token_request = dict(parse_qsl(responses.calls[0].request.body))
    assert token_request["code_verifier"] == code_verifier
    assert "code_verifier" not in blueprint.token_url_params
    assert storage.token["access_token"] == "access-token"
    assert storage.token["refresh_token"] == "refresh-token"


@pytest.mark.parametrize(
    "provider,factory,provider_kwargs,token_url,api_path,api_url",
    PROVIDERS,
)
@responses.activate
def test_provider_refresh_persists_to_storage(
    provider, factory, provider_kwargs, token_url, api_path, api_url
):
    storage = MemoryStorage(
        {
            "access_token": "old-access-token",
            "refresh_token": "old-refresh-token",
            "token_type": "bearer",
            "expires_at": 1,
        }
    )
    app, blueprint = make_provider_app(factory, provider_kwargs, storage)
    responses.add(
        responses.POST,
        token_url,
        json={
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "token_type": "bearer",
            "expires_in": 3600,
        },
    )
    responses.add(responses.GET, api_url, json={"ok": True})

    with app.test_request_context("/"):
        response = blueprint.session.get(api_path)

    assert response.status_code == 200
    refresh_request = dict(parse_qsl(responses.calls[0].request.body))
    assert refresh_request["grant_type"] == "refresh_token"
    assert refresh_request["refresh_token"] == "old-refresh-token"
    assert responses.calls[1].request.headers["Authorization"] == (
        "Bearer new-access-token"
    )
    assert storage.token["access_token"] == "new-access-token"
    assert storage.token["refresh_token"] == "new-refresh-token"
    assert storage.token["expires_at"] > 1
