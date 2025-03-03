"""REST authentication handling."""

import os
from typing import Any

import boto3
from requests_aws4auth import AWS4Auth
from singer_sdk.authenticators import (
    APIAuthenticatorBase,
    APIKeyAuthenticator,
    BasicAuthenticator,
    BearerTokenAuthenticator,
    OAuthAuthenticator,
)

import time
import oauthlib.oauth1
from requests_oauthlib import OAuth1Session

class AWSConnectClient:
    """A connection class to AWS Resources."""

    def __init__(self, connection_config, create_signed_credentials: bool = True):
        self.connection_config = connection_config

        # Initialise the variables
        self.create_signed_credentials = create_signed_credentials
        self.aws_auth = None
        self.region = None
        self.credentials = None
        self.aws_service = None
        self.aws_session = None

        # Establish a AWS Client
        self.credentials = self._create_aws_client()

        # Store AWS Signed Credentials
        self._store_aws4auth_credentials()

    def _create_aws_client(self, config=None):
        if not config:
            config = self.connection_config

        # Get the required parameters from config file and/or environment variables
        aws_profile = config.get("aws_profile") or os.environ.get("AWS_PROFILE")
        aws_access_key_id = config.get("aws_access_key_id") or os.environ.get(
            "AWS_ACCESS_KEY_ID"
        )
        aws_secret_access_key = config.get("aws_secret_access_key") or os.environ.get(
            "AWS_SECRET_ACCESS_KEY"
        )
        aws_session_token = config.get("aws_session_token") or os.environ.get(
            "AWS_SESSION_TOKEN"
        )
        aws_region = config.get("aws_region") or os.environ.get("AWS_REGION")
        self.aws_service = config.get("aws_service", None) or os.environ.get(
            "AWS_SERVICE"
        )

        if not config.get("create_signed_credentials", True):
            self.create_signed_credentials = False

        # AWS credentials based authentication
        if aws_access_key_id and aws_secret_access_key:
            self.aws_session = boto3.session.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=aws_region,
                aws_session_token=aws_session_token,
            )
        # AWS Profile based authentication
        elif aws_profile:
            self.aws_session = boto3.session.Session(profile_name=aws_profile)
        else:
            self.aws_session = None

        if self.aws_session:
            self.region = self.aws_session.region_name
            return self.aws_session.get_credentials()
        else:
            return None

    def _store_aws4auth_credentials(self):
        """Store the AWS Signed Credential for the available AWS credentials.

        Returns:
            The None.

        """
        if self.create_signed_credentials and self.credentials:
            self.aws_auth = AWS4Auth(
                self.credentials.access_key,
                self.credentials.secret_key,
                self.region,
                self.aws_service,
                aws_session=self.credentials.token,
            )
        else:
            self.aws_auth = None

    def get_awsauth(self):
        """Return the AWS Signed Connection for provided credentials.

        Returns:
            The awsauth object.

        """
        return self.aws_auth

    def get_aws_session_client(self):
        """Return the AWS Signed Connection for provided credentials.

        Returns:
            The an AWS Session Client.

        """
        return self.aws_session.client(self.aws_service, region_name=self.region)

class OAuthAuthenticator:
    """Base class for OAuth authentication."""
    def __init__(self, config):
        self.config = config
        self.auth_headers = {}

    def is_token_valid(self):
        """Placeholder method to check token validity."""
        return False

    def update_access_token(self):
        """Placeholder method to update access token."""
        pass

class ConfigurableOAuth1Authenticator(OAuthAuthenticator):
    """Configurable OAuth 1.0 Authenticator."""

    def __init__(self, config):
        super().__init__(config)
        self.oauth_session = None

    def get_initial_oauth_token(self):
        """Get OAuth 1.0 token for authentication."""
        if not self.is_token_valid():
            self.update_access_token()

        self.auth_headers["Authorization"] = self.oauth_session.auth.client.get_oauth_params()

    @property
    def oauth_request_body(self) -> dict:
        """Build OAuth 1.0 parameters."""
        if self.config:
            my_config = self.config
        elif self._config:
            my_config = self._config
        else:
            raise ValueError("Missing configuration for OAuth 1.0.")

        consumer_key = my_config.get("consumer_key")
        consumer_secret = my_config.get("consumer_secret")
        access_token = my_config.get("access_token")
        access_token_secret = my_config.get("access_token_secret")

        if not (consumer_key and consumer_secret and access_token and access_token_secret):
            raise ValueError("Missing required OAuth 1.0 parameters.")

        self.oauth_session = OAuth1Session(
            client_key=consumer_key,
            client_secret=consumer_secret,
            resource_owner_key=access_token,
            resource_owner_secret=access_token_secret
        )

        return {
            "oauth_consumer_key": consumer_key,
            "oauth_token": access_token,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": str(int(time.time())),
            "oauth_nonce": oauthlib.oauth1.generate_nonce(),
            "oauth_version": "1.0"
        }


def select_authenticator(self) -> Any:
    """Call an appropriate SDK Authentication method.

    Calls an appropriate SDK Authentication method based on the the set auth_method.
    If an auth_method is not provided, the tap will call the API using any settings from
    the headers and params config.
    Note: Each auth method requires certain configuration to be present see README.md
    for each auth methods configuration requirements.

    Raises:
        ValueError: if the auth_method is unknown.

    Returns:
        A SDK Authenticator or None if no auth_method supplied.

    """
    # Test where the config is located in self
    if self.config:  # Tap Config
        my_config = self.config
    elif self._config:  # Stream Config
        my_config = self._config

    auth_method = my_config.get("auth_method", "")
    api_keys = my_config.get("api_keys", "")
    self.http_auth = None

    # Set http headers if headers are supplied
    # Some OAUTH2 API's require headers to be supplied
    # In the OAUTH request.
    auth_headers = my_config.get("headers", None)

    # Using API Key Authenticator, keys are extracted from api_keys dict
    if auth_method == "api_key":
        if api_keys:
            for k, v in api_keys.items():
                key = k
                value = v
        return APIKeyAuthenticator(stream=self, key=key, value=value)
    # Using Basic Authenticator
    elif auth_method == "basic":
        return BasicAuthenticator(
            stream=self,
            username=my_config.get("username", ""),
            password=my_config.get("password", ""),
        )
    # Using OAuth Authenticator
    elif auth_method == "oauth":
        return ConfigurableOAuthAuthenticator(
            stream=self,
            auth_endpoint=my_config.get("access_token_url", ""),
            oauth_scopes=my_config.get("scope", ""),
            default_expiration=my_config.get("oauth_expiration_secs", ""),
            oauth_headers=auth_headers,
        )
    # Using Bearer Token Authenticator
    elif auth_method == "bearer_token":
        return BearerTokenAuthenticator(
            stream=self,
            token=my_config.get("bearer_token", ""),
        )
    # Using AWS Authenticator
    elif auth_method == "aws":
        # Establish an AWS Connection Client and returned Signed Credentials
        self.aws_connection = AWSConnectClient(
            connection_config=my_config.get("aws_credentials", None)
        )

        if self.aws_connection.aws_auth:
            self.http_auth = self.aws_connection.aws_auth
        else:
            self.http_auth = None

        return self.http_auth
    elif auth_method != "no_auth":
        self.logger.error(
            f"Unknown authentication method {auth_method}. Use api_key, basic, oauth, "
            f"bearer_token, or aws."
        )
        raise ValueError(
            f"Unknown authentication method {auth_method}. Use api_key, basic, oauth, "
            f"bearer_token, or aws."
        )


def get_authenticator(self) -> Any:
    """Retrieve the appropriate authenticator in tap and stream.

    If the authenticator already exists, use the cached
    Authenticator

    Note: Store the authenticator in class variables used by the SDK.

    Returns:
        None

    """
    # Test where the config is located in self
    if self.config:  # Tap Config
        my_config = self.config
    elif self._config:  # Stream Config
        my_config = self._config

    auth_method = my_config.get("auth_method", None)
    self.http_auth = None

    if not self._authenticator:
        self._authenticator = select_authenticator(self)
        if not self._authenticator:
            # No Auth Method, use default Authenticator
            self._authenticator = APIAuthenticatorBase(stream=self)
    if auth_method == "oauth":
        if not self._authenticator.is_token_valid():
            # Obtain a new OAuth token as it has expired
            self._authenticator = select_authenticator(self)
    if auth_method == "aws":
        # Set the http_auth which is used in the Request call for AWS
        self.http_auth = self._authenticator
