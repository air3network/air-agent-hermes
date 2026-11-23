"""AIR Agent KYA: tool handlers, approval hook, `hermes air` CLI and `/air` slash command."""

from __future__ import annotations

import argparse
import json
import threading
import time

import httpx

from . import air
from .kya import MOCK_PROFILES, VisitError, describe_disclosure, discover, site_base, site_client, terms_digest, visit

DEFAULT_AGENT_LABEL = "Hermes (AIR Agent KYA)"
ENV_SETTINGS = ("partner_id", "console_url", "api_url", "credential_api_url")

_ctx = None


def bind_ctx(ctx) -> None:
    global _ctx
    _ctx = ctx


def setting(key: str, default):
    if _ctx is None:
        return default
    try:
        return _ctx.get_config(key, default=default)
    except Exception:
        return default


def _env() -> air.AirEnv:
    return air.air_env({k: setting(k, "") for k in ENV_SETTINGS})


def _dir():
    return air.agent_dir(setting("agent_dir", "") or None)


def _whoami() -> dict:
    d = air.load_delegation(_dir())
    env = _env()
    if not d:
        return {"delegated": False, "console": env.console_url, "hint": "Run `hermes air login` in a terminal."}
    return {"delegated": True, "userId": d.user_id, "partnerId": d.partner_id(env), "console": env.console_url}


def _allow_local(mock: str | None) -> bool:
    return bool(mock) or bool(setting("allow_local_sites", False))


def _mock_air_url() -> str:
    return air.check_mock_air_url(setting("mock_air_url", air.MOCK_AIR_URL) or air.MOCK_AIR_URL)


def _air_client() -> httpx.Client:
    """Client for AIR endpoints (from settings, not the model). Model-chosen sites use `site_client`."""
    return httpx.Client(timeout=20.0, follow_redirects=False)


def _run_visit(site: str, mock: str | None, log=lambda _: None, *, confirm=None, present: bool = True) -> dict:
    # The model picks `site`: those requests only reach public addresses (loopback too in mock mode or with
    # allow_local_sites). AIR endpoints come from settings, so they keep a plain client.
    allow_local = _allow_local(mock)
    with _air_client() as http, site_client(allow_local=allow_local) as site_http:
        return visit(site, http=http, site_http=site_http, mock=mock or None, env=_env(),
                     delegation=air.load_delegation(_dir()), mock_air_url=_mock_air_url() if mock else air.MOCK_AIR_URL,
                     allow_local=allow_local, confirm=confirm, present=present, log=log)


# --------------------------------------------------------------------------- approval binding
#
# Hermes' approval gate runs in pre_tool_call, before the tool. The hook reads the site's discovery itself, so the
# prompt names the fields, and records the terms it asked about. The tool then discloses only if its own discovery
# returns those same terms; a site that changes its request in between gets nothing.

APPROVAL_TTL = 600.0
_asked: dict[tuple[str, str], tuple[str, float]] = {}
_asked_lock = threading.Lock()


def _approval_needed(args: dict) -> bool:
    return (bool(setting("require_approval", True)) and not args.get("mock_profile")
            and air.load_delegation(_dir()) is not None)


def _ask_key(session_id: str, base: str) -> tuple[str, str]:
    return (session_id or "", base)


def _discover_terms(site: str) -> dict | None:
    """The disclosure terms a live visit to `site` would use, or None when it would disclose nothing."""
    allow_local = _allow_local(None)
    base = site_base(site, allow_local=allow_local)
    with site_client(allow_local=allow_local) as site_http:
        terms, meta = discover(base, site_http)
    if not meta["configured"] or terms["environment"] == "mock":
        return None  # the tool stops with policy_not_configured / MOCK_REQUIRED before anything is sent
    return terms


def _remember(session_id: str, terms: dict, now: float | None = None) -> None:
    now = time.time() if now is None else now
    with _asked_lock:
        for key, (_, at) in list(_asked.items()):
            if now - at > APPROVAL_TTL:
                del _asked[key]
        _asked[_ask_key(session_id, terms["site"])] = (terms_digest(terms), now)


def _approved_confirm(session_id: str):
    """`visit(confirm=...)` for the tool: the terms must match the ones the user was just asked about."""

    def confirm(terms: dict) -> None:
        with _asked_lock:
            asked = _asked.pop(_ask_key(session_id, terms["site"]), None)
        if asked is None or time.time() - asked[1] > APPROVAL_TTL:
            raise VisitError("No approval on record for this disclosure; nothing was shared. Call kya_visit again so "
                             "the user is asked.", code="APPROVAL_MISSING")
        if asked[0] != terms_digest(terms):
            raise VisitError(f"The site changed what it asks for after the user approved; nothing was shared. It now "
                             f"asks for {describe_disclosure(terms)}. Call kya_visit again so the user is asked about "
                             "this.", code="TERMS_CHANGED", requested_fields=terms["requested_fields"])

    return confirm


# --------------------------------------------------------------------------- tools


def air_whoami(args: dict, **kwargs) -> str:
    try:
        return json.dumps(_whoami())
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def kya_visit(args: dict, **kwargs) -> str:
    site = (args.get("site") or "").strip()
    if not site:
        return json.dumps({"error": "site is required"})
    try:
        confirm = _approved_confirm(kwargs.get("session_id") or "") if _approval_needed(args) else None
        return json.dumps(_run_visit(site, args.get("mock_profile"), confirm=confirm), default=str)
    except VisitError as exc:
        return json.dumps({"error": str(exc), **exc.extra})
    except air.AirError as exc:
        return json.dumps({"error": str(exc), "code": exc.code, "retryable": exc.retryable})
    except httpx.HTTPError as exc:
        return json.dumps({"error": f"{type(exc).__name__}: {exc}"})
    except Exception as exc:  # never raise into the agent loop
        return json.dumps({"error": f"unexpected: {exc}"})


# --------------------------------------------------------------------------- hook


def pre_tool_call(tool_name: str = "", args: dict | None = None, session_id: str = "", **kwargs):
    """Escalate live kya_visit to Hermes' human-approval gate, naming the site and the exact fields it requests."""
    args = args or {}
    if tool_name != "kya_visit" or not _approval_needed(args):
        return None  # other tools, approval off, mock data, or nothing to disclose
    try:
        terms = _discover_terms((args.get("site") or "").strip())
    except Exception:
        return None  # the tool repeats discovery, reports the error, and won't disclose without an approval on record
    if terms is None:
        return None
    _remember(session_id, terms)
    return {"action": "approve",
            "message": f"Let AIR share {describe_disclosure(terms)}? Nothing else leaves AIR.",
            # "Always" then covers these exact terms only, not whatever the site asks for next.
            "rule_key": f"kya_visit:{terms_digest(terms)}"}


# --------------------------------------------------------------------------- CLI: hermes air ...


def cli_setup(subparser) -> None:
    subs = subparser.add_subparsers(dest="air_command")
    p_login = subs.add_parser("login", help="Delegate your AIR identity to this agent (AIR Console device code)")
    p_login.add_argument("--name", default=DEFAULT_AGENT_LABEL)
    subs.add_parser("whoami", help="Show the stored delegation")
    subs.add_parser("logout", help="Delete the local agent key (also revoke it in the AIR Console)")
    p_visit = subs.add_parser("visit", help="Enter a KYA site and print its catalog")
    p_visit.add_argument("site")
    p_visit.add_argument("--mock", choices=MOCK_PROFILES)
    p_visit.add_argument("--json", action="store_true")
    subparser.set_defaults(func=cli_handler)


def cli_handler(args: argparse.Namespace) -> None:
    cmd = getattr(args, "air_command", None)
    try:
        if cmd == "login":
            env = _env()
            directory = _dir()
            bundle = air.login(env, args.name, print, directory=directory)
            print(f"Delegated. userId={bundle['userId']} partnerId={bundle.get('partnerId') or env.partner_id}")
            print(f"Key and bundle stored in {directory} (0600). Revoke anytime in the AIR console.")
        elif cmd == "whoami":
            print(json.dumps(_whoami(), indent=2))
        elif cmd == "logout":
            air.logout(_dir(), include_legacy=not setting("agent_dir", ""))
            print("Local agent key removed. Also revoke the key in the AIR console.")
        elif cmd == "visit":
            quiet = args.json
            # Never presents a live credential: a model with a terminal tool could run this without asking.
            result = _run_visit(args.site, args.mock, log=(lambda _: None) if quiet else print, present=False)
            if quiet:
                print(json.dumps(result.get("catalog")))
            else:
                cat = result.get("catalog")
                cat = cat if isinstance(cat, dict) else {}
                if cat.get("catalog"):
                    print(f"             catalog: {cat['catalog']}")
                for p in cat.get("products") or []:
                    if isinstance(p, dict) and isinstance(p.get("priceMinor"), (int, float)):
                        print(f"             {str(p.get('sku')):<19} {str(p.get('title')):<28} ${p['priceMinor'] / 100:.2f}")
                if result.get("note"):
                    print(f"             {result['note']}")
        else:
            print("Usage: hermes air login [--name N] | whoami | logout | visit <siteUrl> [--mock <profile>] [--json]")
    except (air.AirError, VisitError, httpx.HTTPError) as exc:
        print(f"air: {exc}")


# --------------------------------------------------------------------------- slash: /air


def slash_air(raw_args: str) -> str:
    if (raw_args.strip() or "whoami") == "whoami":
        return json.dumps(_whoami(), indent=2)
    return "Usage: /air whoami   (login happens in a terminal: hermes air login)"
