"""Security boundary for the PowerPoint MCP resource server."""
import contextvars
import hashlib
import logging
import os
import time
from collections.abc import MutableMapping
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import jwt
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.shared.exceptions import MCPError

CLIENT_ID = "mcp-dcs-ppt"
AUDIENCES = (
    "https://mcp-servers.fmpn.fr/powerpoint/api/mcp",
    "https://mcp-servers.shared.mpn/powerpoint/api/mcp",
)
READ = "powerpoint:read"
WRITE = "powerpoint:write"
LOGGER = logging.getLogger(__name__)
READ_TOOLS = frozenset({"open_presentation", "get_presentation_info", "get_model_file_info",
                        "get_slide_info", "extract_slide_text", "extract_presentation_text",
                        "list_file_models", "list_slide_templates", "get_layout_template_info",
                        "list_presentations", "get_server_info"})
WRITE_TOOLS = frozenset({"create_presentation", "create_presentation_from_model", "save_presentation",
    "set_core_properties", "switch_presentation", "add_slide", "populate_placeholder",
    "add_bullet_points", "manage_text", "manage_image", "add_table", "format_table_cell",
    "add_shape", "add_chart", "apply_professional_design", "apply_picture_effects", "manage_fonts",
    "apply_slide_layout_template", "create_slide_from_layout_template",
    "create_presentation_from_layout_sequence", "auto_generate_presentation", "optimize_slide_text",
    "manage_hyperlinks", "update_chart_data", "add_connector", "manage_slide_masters",
    "manage_slide_transitions"})

_session = contextvars.ContextVar("ppt_session", default=None)
_states = {}
_LAST_USED = {}
_SESSION_IDLE_SECONDS = 3600


def _normalize_scope_claims(claims):
    """Return normalized OAuth scopes or None for malformed/conflicting claims."""
    normalized = {}
    for claim_name in ("scope", "scp"):
        if claim_name not in claims:
            continue
        value = claims[claim_name]
        if isinstance(value, str):
            scopes = value.split()
        elif isinstance(value, list) and all(
            isinstance(item, str) and item and not any(char.isspace() for char in item)
            for item in value
        ):
            scopes = value
        else:
            return None
        if not scopes:
            return None
        normalized[claim_name] = scopes
    if not normalized:
        return None
    if len(normalized) == 2 and set(normalized["scope"]) != set(normalized["scp"]):
        return None
    return list(normalized["scope"] if "scope" in normalized else normalized["scp"])


class SessionPresentations(MutableMapping):
    def _data(self):
        key = _session.get()
        if key is None:
            raise RuntimeError("No authorized presentation session")
        return _states.setdefault(key, {"presentations": {}, "current": None})["presentations"]

    def __getitem__(self, key): return self._data()[key]
    def __setitem__(self, key, value):
        self._data()[key] = value
        set_current_id(key)
    def __delitem__(self, key): del self._data()[key]
    def __iter__(self): return iter(self._data())
    def __len__(self): return len(self._data())


def current_id():
    key = _session.get()
    return _states.get(key, {}).get("current")


def set_current_id(value):
    key = _session.get()
    if key is None:
        raise RuntimeError("No authorized presentation session")
    _states.setdefault(key, {"presentations": {}, "current": None})["current"] = value


class OIDCVerifier:
    def __init__(self, issuer):
        self.issuer = issuer

    async def verify_token(self, token):
        def rejected(reason):
            LOGGER.warning("OIDC access token rejected: %s", reason)
            return None

        try:
            async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
                response = await client.get(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
                response.raise_for_status()
                discovery = response.json()
                jwks_url = discovery["jwks_uri"]
                if discovery["issuer"] != self.issuer or urlsplit(jwks_url).scheme != "https":
                    return rejected("invalid_discovery_metadata")
                response = await client.get(jwks_url)
                response.raise_for_status()
                keys = jwt.PyJWKSet.from_dict(response.json()).keys
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
                return rejected("invalid_token_header")
            matching = [k for k in keys if k.key_id == header["kid"] and k.algorithm_name == "RS256"]
            if len(matching) != 1:
                return rejected("signing_key_not_found")
            claims = jwt.decode(token, matching[0].key, algorithms=["RS256"], issuer=self.issuer,
                                audience=list(AUDIENCES), options={"require": ["iss", "aud", "exp", "iat", "jti", "sub"]})
            raw_audience = claims.get("aud")
            audiences = ([raw_audience] if isinstance(raw_audience, str)
                         else raw_audience if isinstance(raw_audience, list)
                         and all(isinstance(item, str) for item in raw_audience) else [])
            if not set(audiences).intersection(AUDIENCES) or (claims.get("client_id") or claims.get("azp")) != CLIENT_ID:
                return rejected("audience_or_client_mismatch")
            if "azp" in claims and claims["azp"] != CLIENT_ID:
                return rejected("authorized_party_mismatch")
            if not all(isinstance(claims.get(k), str) and claims[k].strip() for k in ("sub", "jti")):
                return rejected("subject_or_token_id_missing")
            scopes = _normalize_scope_claims(claims)
            if scopes is None:
                return rejected("invalid_scope_claim")
            if not set(scopes).intersection({READ, WRITE}):
                return rejected("required_scope_missing")
            return AccessToken(token=token, client_id=CLIENT_ID, subject=claims["sub"],
                               scopes=scopes, expires_at=claims["exp"], claims={"iss": self.issuer})
        except jwt.InvalidAudienceError:
            return rejected("invalid_audience")
        except jwt.InvalidIssuerError:
            return rejected("invalid_issuer")
        except jwt.MissingRequiredClaimError:
            return rejected("required_claim_missing")
        except jwt.PyJWTError:
            return rejected("invalid_jwt")
        except httpx.HTTPError:
            return rejected("oidc_dependency_unavailable")
        except (ValueError, KeyError, TypeError):
            return rejected("invalid_oidc_response")


def _bounded_path(value, root):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid path")
    root = root.resolve()
    candidate = Path(value)
    candidate = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if not candidate.is_relative_to(root) or candidate == root:
        raise ValueError("Path is outside the permitted root")
    return str(candidate)


def _paths(name, arguments, workspace, templates):
    args = dict(arguments)
    for key in ("file_path", "font_path", "output_path"):
        if args.get(key) is not None:
            args[key] = _bounded_path(args[key], workspace)
    if args.get("template_path") is not None:
        args["template_path"] = _bounded_path(args["template_path"], templates)
    if name == "manage_image" and args.get("source_type", "file") != "base64":
        args["image_source"] = _bounded_path(args.get("image_source"), workspace)
    if name in {"manage_image", "manage_fonts"} and args.get("operation") in {"enhance", "optimize"} and not args.get("output_path"):
        raise ValueError("An output path in the workspace is required")
    if args.get("image_paths") is not None:
        args["image_paths"] = {k: _bounded_path(v, workspace) for k, v in args["image_paths"].items()}
    if name == "create_presentation_from_layout_sequence":
        sequence = []
        for item in args.get("template_sequence", []):
            item = dict(item)
            if "images" in item:
                item["images"] = {k: _bounded_path(v, workspace) for k, v in item["images"].items()}
            sequence.append(item)
        if "template_sequence" in args:
            args["template_sequence"] = sequence
    return args


class SecurityMiddleware:
    async def __call__(self, ctx, call_next):
        if ctx.method != "tools/call":
            return await call_next(ctx)
        request = ctx.request
        user = request.scope.get("user") if request is not None else None
        local = os.environ.get("PPT_AUTH_MODE") == "local"
        if isinstance(user, AuthenticatedUser):
            access = user.access_token
            subject = access.subject
            scopes = set(access.scopes)
        elif local:
            subject, scopes = "local", {READ, WRITE}
        else:
            raise MCPError(-32600, "Authentication required")
        params = dict(ctx.params or {})
        name = params.get("name")
        required = READ if name in READ_TOOLS else WRITE if name in WRITE_TOOLS else None
        if required is None or required not in scopes:
            raise MCPError(-32600, "Not authorized")
        session_id = request.headers.get("mcp-session-id") if request is not None else "local"
        if not session_id:
            raise MCPError(-32600, "Session required")
        subject_key = hashlib.sha256(subject.encode()).hexdigest()
        workspace_root = Path(os.environ.get("PPT_WORKSPACE_ROOT", "/workspace")).resolve()
        workspace = workspace_root / subject_key
        if workspace.is_symlink():
            raise MCPError(-32602, "Invalid workspace")
        templates = Path(os.environ.get("PPT_TEMPLATE_PATH", "/app/templates"))
        try:
            params["arguments"] = _paths(name, params.get("arguments") or {}, workspace, templates)
        except (ValueError, TypeError, AttributeError):
            raise MCPError(-32602, "Invalid file path") from None
        workspace.mkdir(parents=True, exist_ok=True)
        now = time.monotonic()
        key = (subject_key, session_id)
        for old_key, last_used in list(_LAST_USED.items()):
            if now - last_used > _SESSION_IDLE_SECONDS:
                _LAST_USED.pop(old_key, None)
                _states.pop(old_key, None)
        if key not in _LAST_USED and len(_LAST_USED) >= 1000:
            raise MCPError(-32600, "Session capacity reached")
        _LAST_USED[key] = now
        marker = _session.set(key)
        try:
            result = await call_next(replace(ctx, params=params))
            return result
        finally:
            _session.reset(marker)
