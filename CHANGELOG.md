# Changelog

## Unreleased

- The approval prompt names the site and the exact fields. The `pre_tool_call` hook now reads the
  site's `/.well-known/air-kya` before asking, and `kya_visit` discloses only if its own discovery
  returns the same site, environment, programId and fields; otherwise nothing is sent
  (`TERMS_CHANGED`), and a disclosure with no approval on record is refused (`APPROVAL_MISSING`).
  "Always" approvals now cover those exact terms only (`rule_key` per terms).
- `hermes air visit` never presents a live credential: it always gets the catalog for unverified
  agents (`verification: withheld`). Disclosure goes through `kya_visit` and its approval only.
- `hermes air logout` sticks: the old `air-kya` delegation is now moved, not copied, a marker stops a
  second migration, and logout also deletes any copy an earlier version left behind.
- Store content is treated as untrusted: discovery claim names, programId and environment are
  validated before anything is sent (`INVALID_DISCOVERY`); the catalog is returned with a notice that
  it is data, the presentation redacted if echoed back, control and format characters removed, and
  size capped at 20,000 characters (`catalog_truncated`); `X-AIR-*` headers are validated.
- `issueUrl` is passed on only on the site's own origin or an https `air3.com` host; other hosts are
  named in `issue_url_withheld`, not linked.
- `console_url`, `api_url` and `credential_api_url` must be https on `air3.com` or a subdomain
  (`ENDPOINT_NOT_ALLOWED`); `mock_air_url` must be loopback.


## 0.1.2

- `kya_visit` only reaches sites on public addresses. Each site connection resolves the host, refuses
  it unless every address is public (no private, loopback, link-local, CGNAT or cloud-metadata
  addresses, IP literals included), and connects to the address it checked, so DNS rebinding can't
  get around it. Site requests ignore proxy environment variables and don't follow redirects.
- Localhost sites (http or https) work only in mock mode or with the new `allow_local_sites` setting
  (default off). Plain http to localhost outside mock mode is no longer allowed by default.
- `httpcore` is now a declared dependency (it was already pulled in by `httpx`).

## 0.1.0

First release as **AIR Agent KYA**.

- Renamed to **AIR Agent KYA**: plugin `air-agent-kya` (was `air-kya`), skill `air-agent-kya`,
  toolset `air_agent_kya`. Commands (`hermes air …`, `/air`) and tools (`kya_visit`, `air_whoami`)
  are unchanged.
- An existing delegation under the old `air-kya` plugin-data dir is copied over on first use, so no
  new `hermes air login` is needed.
- Endpoint and storage overrides moved from environment variables (`AIR_PARTNER_ID`,
  `AIR_CONSOLE_URL`, `AIR_API_URL`, `AIR_CREDENTIAL_API_URL`, `AIR_KYA_AGENT_DIR`) to plugin settings
  (`partner_id`, `console_url`, `api_url`, `credential_api_url`, `agent_dir`). Defaults unchanged.
- `requires_hermes: ">=0.23.0"`, author, LICENSE, CI, disclosures and catalog entry draft added.

## Pre-release history (as `air-kya`)

### air-kya 0.2.1

- An agent that isn't delegated now gets the site's no-proof (Standard) catalog with a hint, instead
  of a `NOT_DELEGATED` error.
- `hermes air visit` prints the catalog name (Standard / VIP).

### air-kya 0.2.0

- Rewritten to match mocaverse/air-kya `agent/`: AIR Console device-code login, SPKI PEM session
  proof, `/.well-known/air-kya`, `POST /kya/challenge`, `X-AIR-KYA`, mock profiles.

### air-kya 0.1.0

- First draft (superseded).
