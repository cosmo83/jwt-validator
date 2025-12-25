#!/usr/bin/env python3
"""
Dynamic JWT Validator for Multi-Tenant XSUAA
Extracts issuer from JWT, performs OIDC discovery, and validates signature
"""

import json
import re
import time
from functools import lru_cache
from typing import Dict, Optional, Tuple

import jwt
import requests
from flask import Flask, request, jsonify
from jwt import PyJWKClient

app = Flask(__name__)

# Configuration
ALLOWED_ISSUER_PATTERN = re.compile(
    r'^https://[a-zA-Z0-9-]+\.authentication\.in30\.hana\.ondemand\.com/oauth/token$'
)
OIDC_DISCOVERY_CACHE_TTL = 3600  # 1 hour
JWKS_CACHE_TTL = 3600  # 1 hour

# Cache for OIDC discovery documents
_oidc_discovery_cache: Dict[str, Tuple[dict, float]] = {}


@lru_cache(maxsize=100)
def get_oidc_discovery(issuer: str) -> Optional[dict]:
    """
    Fetch OIDC discovery document from issuer.
    Uses caching to avoid repeated requests.
    """
    # Check cache
    if issuer in _oidc_discovery_cache:
        doc, timestamp = _oidc_discovery_cache[issuer]
        if time.time() - timestamp < OIDC_DISCOVERY_CACHE_TTL:
            return doc

    # Remove /oauth/token suffix if present to get base URL
    base_issuer = issuer.rstrip('/').replace('/oauth/token', '')
    discovery_url = f"{base_issuer}/.well-known/openid-configuration"

    try:
        app.logger.info(f"Fetching OIDC discovery from: {discovery_url}")
        response = requests.get(discovery_url, timeout=5)
        response.raise_for_status()
        doc = response.json()

        # Cache the result
        _oidc_discovery_cache[issuer] = (doc, time.time())
        return doc
    except Exception as e:
        app.logger.error(f"Failed to fetch OIDC discovery: {e}")
        return None


def validate_jwt_token(token: str) -> Tuple[bool, Optional[dict], str]:
    """
    Validate JWT token with dynamic issuer discovery.

    Returns:
        (is_valid, decoded_token, error_message)
    """
    try:
        # Step 1: Decode JWT without verification to get issuer
        unverified = jwt.decode(token, options={"verify_signature": False})
        issuer = unverified.get('iss')

        if not issuer:
            return False, None, "JWT missing 'iss' claim"

        app.logger.info(f"JWT issuer: {issuer}")

        # Step 2: Validate issuer pattern
        if not ALLOWED_ISSUER_PATTERN.match(issuer):
            return False, None, f"Issuer not allowed: {issuer}"

        # Step 3: Fetch OIDC discovery to get JWKS URI
        oidc_config = get_oidc_discovery(issuer)
        if not oidc_config:
            return False, None, "Failed to fetch OIDC discovery"

        jwks_uri = oidc_config.get('jwks_uri')
        if not jwks_uri:
            return False, None, "JWKS URI not found in OIDC discovery"

        app.logger.info(f"Using JWKS URI: {jwks_uri}")

        # Step 4: Validate JWT signature using JWKS
        jwks_client = PyJWKClient(jwks_uri, cache_keys=True, max_cached_keys=10)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Step 5: Fully validate and decode JWT
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True
            }
        )

        return True, decoded, ""

    except jwt.ExpiredSignatureError:
        return False, None, "Token expired"
    except jwt.InvalidTokenError as e:
        return False, None, f"Invalid token: {str(e)}"
    except Exception as e:
        app.logger.error(f"JWT validation error: {e}", exc_info=True)
        return False, None, f"Validation error: {str(e)}"


@app.route('/validate', methods=['GET', 'POST'])
def validate():
    """
    Validate JWT from Authorization header.
    Returns user info if valid, error otherwise.
    """
    # Extract Authorization header
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header[7:]  # Remove 'Bearer ' prefix

    # Validate token
    is_valid, decoded, error = validate_jwt_token(token)

    if not is_valid:
        app.logger.warning(f"JWT validation failed: {error}")
        return jsonify({"error": error}), 401

    # Extract user info
    user_name = decoded.get('user_name', decoded.get('sub', 'unknown'))
    tenant_id = decoded.get('zid', 'unknown')

    # Return success with user info in headers (for Trino integration)
    response = jsonify({
        "valid": True,
        "user": user_name,
        "tenant": tenant_id,
        "claims": decoded
    })

    # Add headers that will be forwarded to Trino by ext_authz
    response.headers['X-Trino-User'] = user_name
    response.headers['X-Forwarded-User'] = user_name
    response.headers['X-Tenant-Id'] = tenant_id

    return response, 200


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200


@app.route('/ready', methods=['GET'])
def ready():
    """Readiness check endpoint"""
    return jsonify({"status": "ready"}), 200


if __name__ == '__main__':
    # This is only used for local development
    # In production, gunicorn is used instead
    import os
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
