"""Apify Actor entrypoint for upi-id-osint v0.3.

UPI ID OSINT — direct phone-to-VPA-to-name lookup.

Engines:
  Razorpay frontend /v1/payments/validate/account?key_id=...  → phone → active VPAs (FREE)
  PayU /merchant/postservice?form=2  validateVPA               → VPA → bank-registered name (~₹1-3)

Modes:
  A. phone               (single string)  → enumerate phone-based VPAs
  B. vpa                 (single string)  → direct lookup
  C. phone + vpa         (both strings)   → combined
  D. phones[] + vpas[]   (arrays)         → bulk independent processing

Outputs:
  One dataset item per target. Each item includes raw upstream responses
  for full audit trail, plus parsed fields and a confidence score.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import ssl
import time
from typing import Any

import aiohttp
import certifi
from apify import Actor

_SSL_CTX = ssl.create_default_context(cafile=certifi.where())

# ---------------------------------------------------------------------------
# 35-handle NPCI taxonomy
# ---------------------------------------------------------------------------
HANDLES: dict[str, dict[str, Any]] = {
    "ybl":         {"psp": "PhonePe",        "bank": "Yes Bank",            "tier": 1},
    "ibl":         {"psp": "PhonePe",        "bank": "IndusInd Bank",       "tier": 1},
    "axl":         {"psp": "PhonePe",        "bank": "Axis Bank",           "tier": 1},
    "oksbi":       {"psp": "Google Pay",     "bank": "SBI",                 "tier": 1},
    "okhdfcbank":  {"psp": "Google Pay",     "bank": "HDFC",                "tier": 1},
    "okicici":     {"psp": "Google Pay",     "bank": "ICICI",               "tier": 1},
    "okaxis":      {"psp": "Google Pay",     "bank": "Axis Bank",           "tier": 1},
    "paytm":       {"psp": "Paytm",          "bank": "Paytm Bank (legacy)", "tier": 1},
    "ptyes":       {"psp": "Paytm",          "bank": "Yes Bank",            "tier": 1},
    "ptaxis":      {"psp": "Paytm",          "bank": "Axis Bank",           "tier": 1},
    "ptsbi":       {"psp": "Paytm",          "bank": "SBI",                 "tier": 1},
    "pthdfc":      {"psp": "Paytm",          "bank": "HDFC",                "tier": 1},
    "upi":         {"psp": "BHIM",           "bank": "NPCI direct",         "tier": 1},
    "apl":         {"psp": "Amazon Pay",     "bank": "Axis Bank",           "tier": 2},
    "yapl":        {"psp": "Amazon Pay",     "bank": "Yes Bank",            "tier": 2},
    "rapl":        {"psp": "Amazon Pay",     "bank": "RBL Bank",            "tier": 2},
    "waicici":     {"psp": "WhatsApp Pay",   "bank": "ICICI",               "tier": 2},
    "waaxis":      {"psp": "WhatsApp Pay",   "bank": "Axis Bank",           "tier": 2},
    "wahdfcbank":  {"psp": "WhatsApp Pay",   "bank": "HDFC",                "tier": 2},
    "wasbi":       {"psp": "WhatsApp Pay",   "bank": "SBI",                 "tier": 2},
    "sbi":         {"psp": "SBI Pay",        "bank": "SBI",                 "tier": 3},
    "icici":       {"psp": "iMobile Pay",    "bank": "ICICI",               "tier": 3},
    "hdfcbank":    {"psp": "HDFC Pay",       "bank": "HDFC",                "tier": 3},
    "axisbank":    {"psp": "Axis Pay",       "bank": "Axis Bank",           "tier": 3},
    "kotak":       {"psp": "Kotak 811",     "bank": "Kotak",               "tier": 3},
    "cred":        {"psp": "Cred",           "bank": "Axis (sponsoring)",   "tier": 3},
    "fam":         {"psp": "FamPay",         "bank": "IDFC First",          "tier": 3},
    "slice":       {"psp": "Slice",          "bank": "Sponsoring",          "tier": 3},
    "jio":         {"psp": "MyJio",          "bank": "Jio Payments",        "tier": 3},
    "airtel":      {"psp": "Airtel Pay",     "bank": "Airtel Payments",     "tier": 3},
    "navi":        {"psp": "Navi",           "bank": "Navi (RBL sponsor)",  "tier": 3},
    "timepay":     {"psp": "TimePay (NPST)", "bank": "NPST sponsor",        "tier": 3},
    "yespop":      {"psp": "Yes Pop",        "bank": "Yes Bank",            "tier": 3},
    "superpay":    {"psp": "SuperPay",       "bank": "Sponsor bank",        "tier": 3},
    "timecosmos":  {"psp": "TimeCosmos",     "bank": "Cosmos Bank",         "tier": 3},
}

DEFAULT_RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
DEFAULT_PAYU_KEY = os.environ.get("PAYU_KEY", "")
DEFAULT_PAYU_SALT = os.environ.get("PAYU_SALT", "")

VPA_REGEX = re.compile(r"^[a-zA-Z0-9._\-]{1,256}@[a-zA-Z][a-zA-Z0-9]{1,64}$")


# ---------------------------------------------------------------------------
# Phone normalization + libphonenumber metadata
# ---------------------------------------------------------------------------
def normalize_phone(raw: str) -> tuple[str, str]:
    cleaned = re.sub(r"[^\d+]", "", raw)
    if cleaned.startswith("+91"):
        digits = cleaned[3:]
    elif cleaned.startswith("91") and len(cleaned) == 12:
        digits = cleaned[2:]
    elif cleaned.startswith("+"):
        digits = cleaned[1:]
    else:
        digits = cleaned
    digits = digits.lstrip("0")
    if not digits.isdigit() or len(digits) < 10:
        raise ValueError(f"Could not extract a 10-digit local number from {raw!r}")
    local = digits[-10:]
    return f"+91{local}", local


def phone_info(phone_input: str) -> dict[str, Any]:
    info: dict[str, Any] = {"valid": False, "is_indian": False}
    try:
        import phonenumbers
        from phonenumbers import geocoder, number_type
        pn = phonenumbers.parse(phone_input, "IN")
        info["valid"] = phonenumbers.is_valid_number(pn)
        info["country"] = phonenumbers.region_code_for_number(pn) or "IN"
        info["region"] = geocoder.description_for_number(pn, "en")
        info["is_indian"] = info["country"] == "IN"
        nt = number_type(pn)
        info["line_type"] = {0: "fixed_line", 1: "mobile", 2: "fixed_or_mobile"}.get(nt, "unknown")
        info["e164"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
        info["national"] = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
    except Exception as e:
        info["error"] = str(e)
    return info


def validate_vpa_format(vpa: str) -> tuple[bool, str | None]:
    if not vpa or not isinstance(vpa, str):
        return False, "VPA is empty or not a string"
    vpa = vpa.strip()
    if "@" not in vpa:
        return False, "VPA missing '@' separator"
    if vpa.count("@") > 1:
        return False, "VPA contains multiple '@' characters"
    user, handle = vpa.split("@", 1)
    if not user:
        return False, "VPA username portion is empty"
    if not handle:
        return False, "VPA handle portion is empty"
    if not VPA_REGEX.match(vpa):
        return False, f"VPA does not match expected format <username>@<handle>"
    return True, None


def parse_vpa(vpa: str) -> tuple[str, str, dict[str, Any]]:
    username, handle = vpa.split("@", 1)
    meta = HANDLES.get(handle, {"psp": "Unknown PSP", "bank": "Unknown bank", "tier": 0})
    return username, handle, meta


# ---------------------------------------------------------------------------
# Engine 1: Razorpay frontend — returns structured result with full audit
# ---------------------------------------------------------------------------
async def razorpay_validate(session: aiohttp.ClientSession, key_id: str, vpa: str) -> dict[str, Any]:
    url = f"https://api.razorpay.com/v1/payments/validate/account?key_id={key_id}"
    out: dict[str, Any] = {"http_status": None, "raw": None, "ok": False, "error": None, "rate_limited": False, "auth_failed": False}
    try:
        async with session.post(url, json={"entity": "vpa", "value": vpa}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            out["http_status"] = r.status
            raw = await r.json(content_type=None)
            out["raw"] = raw
            if r.status == 429:
                out["rate_limited"] = True
                out["error"] = "Razorpay rate-limited (HTTP 429)"
            elif r.status == 401 or (isinstance(raw, dict) and raw.get("error", {}).get("description") == "Authentication failed"):
                out["auth_failed"] = True
                out["error"] = "Razorpay key_id rejected (auth failed)"
            elif r.status >= 400:
                out["error"] = f"Razorpay HTTP {r.status}: {raw}"
            else:
                out["ok"] = True
    except asyncio.TimeoutError:
        out["error"] = "Razorpay timeout (>10s)"
    except Exception as e:
        out["error"] = f"Razorpay request failed: {e}"
    return out


# ---------------------------------------------------------------------------
# Engine 2: PayU validateVPA — returns structured result with full audit
# ---------------------------------------------------------------------------
def payu_hash(key: str, salt: str, vpa: str) -> str:
    return hashlib.sha512(f"{key}|validateVPA|{vpa}|{salt}".encode()).hexdigest()


async def payu_validate(session: aiohttp.ClientSession, key: str, salt: str, vpa: str) -> dict[str, Any]:
    url = "https://secure.payu.in/merchant/postservice?form=2"
    data = {"key": key, "command": "validateVPA", "hash": payu_hash(key, salt, vpa), "var1": vpa}
    out: dict[str, Any] = {"http_status": None, "raw": None, "ok": False, "error": None, "auth_failed": False, "rate_limited": False}
    try:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=15)) as r:
            out["http_status"] = r.status
            raw = await r.json(content_type=None)
            out["raw"] = raw
            if isinstance(raw, dict):
                msg = (raw.get("msg") or raw.get("message") or "").lower()
                if "invalid hash" in msg:
                    out["auth_failed"] = True
                    out["error"] = "PayU rejected hash signature (check key/salt)"
                elif "rate" in msg or "limit reached" in msg or "throttle" in msg:
                    out["rate_limited"] = True
                    out["error"] = f"PayU rate-limited: {raw.get('msg') or raw.get('message')}"
                elif raw.get("status") == 0:
                    out["error"] = f"PayU command rejected: {raw.get('msg') or raw.get('message') or raw}"
                elif raw.get("status") == "SUCCESS":
                    out["ok"] = True
                else:
                    out["error"] = f"Unexpected PayU response: {raw}"
            else:
                out["error"] = f"PayU returned non-JSON: {raw}"
    except asyncio.TimeoutError:
        out["error"] = "PayU timeout (>15s)"
    except Exception as e:
        out["error"] = f"PayU request failed: {e}"
    return out


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------
def normalize_name(n: str) -> str:
    return re.sub(r"\s+", " ", n.strip()).upper()


def compute_confidence(vpas: list[dict[str, Any]]) -> tuple[str | None, list[str], float]:
    names: dict[str, int] = {}
    for v in vpas:
        if v.get("full_name") and v["full_name"] != "NA":
            key = normalize_name(v["full_name"])
            names[key] = names.get(key, 0) + 1
    if not names:
        return None, [], 0.0
    sorted_names = sorted(names.items(), key=lambda x: -x[1])
    primary, count = sorted_names[0]
    alternates = [n for n, _ in sorted_names[1:]]
    confidence = min(1.0, 0.5 + 0.15 * (count - 1))
    if len(sorted_names) > 1:
        confidence -= 0.1
    return primary, alternates, round(max(0.0, confidence), 2)


def app_usage_profile(vpas: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for v in vpas:
        if v["is_active"]:
            counts[v["psp"]] = counts.get(v["psp"], 0) + 1
    if not counts:
        return {"primary": None, "all": [], "not_used": []}
    sorted_psps = sorted(counts.items(), key=lambda x: -x[1])
    all_psps = {info["psp"] for info in HANDLES.values()}
    used = set(counts)
    return {
        "primary": sorted_psps[0][0],
        "all": [{"psp": p, "vpa_count": c} for p, c in sorted_psps],
        "not_used": sorted(all_psps - used),
    }


# ---------------------------------------------------------------------------
# VPA enrichment — build one VPA row, optionally with PayU lookup
# ---------------------------------------------------------------------------
def build_vpa_row(
    vpa: str,
    discovered_via: str,
    rz_result: dict[str, Any] | None,
    pu_result: dict[str, Any] | None,
    phone_local10: str | None,
) -> dict[str, Any]:
    username, handle, meta = parse_vpa(vpa)
    rz_raw = (rz_result or {}).get("raw") or {}
    pu_raw = (pu_result or {}).get("raw") or {}

    rz_success = bool(rz_raw.get("success")) if isinstance(rz_raw, dict) else False
    masked_name = rz_raw.get("customer_name") if isinstance(rz_raw, dict) else None
    rz_active = bool(rz_success and masked_name)

    payu_is_valid = pu_raw.get("isVPAValid") == 1 if isinstance(pu_raw, dict) else False
    full_name = pu_raw.get("payerAccountName") if (isinstance(pu_raw, dict) and payu_is_valid) else None
    if full_name == "NA":
        full_name = None
    is_auto_pay_vpa_valid = pu_raw.get("isAutoPayVPAValid") if isinstance(pu_raw, dict) else None
    is_auto_pay_bank_valid = pu_raw.get("isAutoPayBankValid") if isinstance(pu_raw, dict) else None

    is_active = rz_active or payu_is_valid

    rz_status = "skipped"
    if rz_result:
        if rz_result.get("rate_limited"):
            rz_status = "rate_limited"
        elif rz_result.get("auth_failed"):
            rz_status = "auth_failed"
        elif rz_result.get("error"):
            rz_status = "error"
        elif rz_active:
            rz_status = "active"
        elif rz_success and not masked_name:
            rz_status = "inactive"

    pu_status = None
    if pu_result:
        if pu_result.get("auth_failed"):
            pu_status = "auth_failed"
        elif pu_result.get("rate_limited"):
            pu_status = "rate_limited"
        elif pu_result.get("error"):
            pu_status = "error"
        elif payu_is_valid:
            pu_status = "valid"
        else:
            pu_status = "inactive"

    username_type = "phone_default" if (phone_local10 and username == phone_local10) else "custom"

    err = None
    if rz_result and rz_result.get("error"):
        err = rz_result["error"]
    if pu_result and pu_result.get("error"):
        err = f"{err}; {pu_result['error']}" if err else pu_result["error"]

    return {
        "vpa": vpa,
        "handle": handle,
        "username": username,
        "username_type": username_type,
        "psp": meta["psp"],
        "bank": meta["bank"],
        "is_active": is_active,
        "masked_name": masked_name,
        "full_name": full_name,
        "is_auto_pay_vpa_valid": is_auto_pay_vpa_valid,
        "is_auto_pay_bank_valid": is_auto_pay_bank_valid,
        "razorpay_status": rz_status,
        "payu_status": pu_status,
        "razorpay_raw": rz_raw if isinstance(rz_raw, dict) else None,
        "payu_raw": pu_raw if isinstance(pu_raw, dict) else None,
        "discovered_via": discovered_via,
        "error": err,
    }


# ---------------------------------------------------------------------------
# Build a single dossier (one target)
# ---------------------------------------------------------------------------
async def build_dossier(
    phone: str | None,
    vpa: str | None,
    depth: str,
    razorpay_key_id: str,
    payu_key: str,
    payu_salt: str,
) -> dict[str, Any]:
    sources = ["libphonenumber"]
    warnings: list[str] = []
    errors: list[str] = []
    e164 = None
    local10 = None
    pinfo: dict[str, Any] = {"valid": False}

    # ── Input validation ─────────────────────────────────────────────────
    if phone:
        try:
            e164, local10 = normalize_phone(phone)
            pinfo = phone_info(e164)
            if not pinfo.get("valid"):
                warnings.append(f"phone parsed but libphonenumber says invalid: {e164}")
            if not pinfo.get("is_indian"):
                warnings.append(f"phone country is {pinfo.get('country')} not IN — UPI enumeration likely empty")
            if pinfo.get("line_type") not in ("mobile", "fixed_or_mobile"):
                warnings.append(f"phone line_type is {pinfo.get('line_type')} not mobile — UPI requires mobile")
        except ValueError as e:
            errors.append(f"phone normalization failed: {e}")
            phone = None  # skip enumeration

    if vpa:
        ok, msg = validate_vpa_format(vpa)
        if not ok:
            errors.append(f"vpa input rejected: {msg}")
            vpa = None

    if not phone and not vpa:
        return {
            "input_phone": e164,
            "input_vpa": None,
            "queried_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "sources": sources,
            "primary_name": None, "alternate_names": [], "confidence": 0.0,
            "vpa_count": 0, "psp_primary": None, "phone_valid": False,
            "phone": pinfo, "vpas": [], "app_usage_profile": {"primary": None, "all": [], "not_used": []},
            "warnings": warnings, "errors": errors or ["no valid target — provide phone or vpa"],
        }

    # ── Pick handle set by depth ─────────────────────────────────────────
    if depth == "tier1":
        handles = [h for h, m in HANDLES.items() if m["tier"] == 1]
    elif depth == "tier2":
        handles = [h for h, m in HANDLES.items() if m["tier"] <= 2]
    else:
        handles = list(HANDLES.keys())

    connector = aiohttp.TCPConnector(limit=20, ssl=_SSL_CTX)
    vpas: list[dict[str, Any]] = []

    async with aiohttp.ClientSession(connector=connector) as session:
        # ── MODE A: phone enumeration ────────────────────────────────────
        rz_by_vpa: dict[str, dict[str, Any]] = {}
        candidates: list[str] = []
        if phone and local10:
            candidates = [f"{local10}@{h}" for h in handles]
            if razorpay_key_id:
                sources.append("razorpay_frontend")
                rz_results = await asyncio.gather(*[razorpay_validate(session, razorpay_key_id, v) for v in candidates])
                for c, r in zip(candidates, rz_results):
                    rz_by_vpa[c] = r
                    if r.get("rate_limited"):
                        errors.append(f"Razorpay rate-limited on {c}")
                    if r.get("auth_failed"):
                        errors.append("Razorpay key_id rejected — check razorpayKeyId input")
            else:
                warnings.append("razorpayKeyId not provided — enumeration skipped")

        # ── MODE B: direct VPA lookup ────────────────────────────────────
        direct_rz_result: dict[str, Any] | None = None
        if vpa and vpa not in rz_by_vpa:
            if razorpay_key_id:
                if "razorpay_frontend" not in sources:
                    sources.append("razorpay_frontend")
                direct_rz_result = await razorpay_validate(session, razorpay_key_id, vpa)
                if direct_rz_result.get("rate_limited"):
                    errors.append(f"Razorpay rate-limited on direct {vpa}")
                if direct_rz_result.get("auth_failed"):
                    errors.append("Razorpay key_id rejected on direct lookup")

        # ── Determine which VPAs need PayU name resolution ──────────────
        vpas_to_resolve: list[str] = []
        if phone and local10:
            for c in candidates:
                r = rz_by_vpa.get(c, {})
                if r.get("ok") and isinstance(r.get("raw"), dict) and r["raw"].get("success") and r["raw"].get("customer_name"):
                    vpas_to_resolve.append(c)
        if vpa and vpa not in vpas_to_resolve:
            vpas_to_resolve.append(vpa)  # PayU directly for user-provided VPA regardless of Razorpay outcome

        # ── PayU name resolution ─────────────────────────────────────────
        pu_by_vpa: dict[str, dict[str, Any]] = {}
        if vpas_to_resolve and payu_key and payu_salt:
            if "payu_validateVPA" not in sources:
                sources.append("payu_validateVPA")
            pu_results = await asyncio.gather(*[payu_validate(session, payu_key, payu_salt, v) for v in vpas_to_resolve])
            for v, r in zip(vpas_to_resolve, pu_results):
                pu_by_vpa[v] = r
                if r.get("auth_failed"):
                    errors.append("PayU key/salt rejected — check payuKey/payuSalt input")
                if r.get("rate_limited"):
                    errors.append(f"PayU rate-limited on {v}")
        elif vpas_to_resolve:
            warnings.append("payuKey/payuSalt not provided — full-name resolution skipped")

    # ── Build VPA rows ──────────────────────────────────────────────────
    if phone and local10:
        for c in candidates:
            vpas.append(build_vpa_row(
                vpa=c,
                discovered_via="razorpay_enumeration",
                rz_result=rz_by_vpa.get(c),
                pu_result=pu_by_vpa.get(c),
                phone_local10=local10,
            ))
    if vpa and vpa not in [v["vpa"] for v in vpas]:
        vpas.append(build_vpa_row(
            vpa=vpa,
            discovered_via="direct_vpa_input",
            rz_result=direct_rz_result,
            pu_result=pu_by_vpa.get(vpa),
            phone_local10=local10,
        ))

    primary, alts, conf = compute_confidence(vpas)
    profile = app_usage_profile(vpas)

    return {
        "input_phone": e164,
        "input_vpa": vpa,
        "queried_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "sources": sources,
        "primary_name": primary,
        "alternate_names": alts,
        "confidence": conf,
        "vpa_count": sum(1 for v in vpas if v["is_active"]),
        "psp_primary": profile["primary"],
        "phone_valid": pinfo.get("valid", False),
        "phone": pinfo,
        "vpas": vpas,
        "app_usage_profile": profile,
        "warnings": warnings,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Bulk target list builder
# ---------------------------------------------------------------------------
def collect_targets(actor_input: dict[str, Any]) -> list[tuple[str | None, str | None]]:
    """Return [(phone, vpa), ...] tuples — one per dossier to produce."""
    targets: list[tuple[str | None, str | None]] = []
    phone_str = (actor_input.get("phone") or "").strip() or None
    vpa_str = (actor_input.get("vpa") or "").strip() or None
    phones_arr = [p.strip() for p in (actor_input.get("phones") or []) if p and p.strip()]
    vpas_arr = [v.strip() for v in (actor_input.get("vpas") or []) if v and v.strip()]

    # Backward-compat: single phone + single vpa → one combined dossier
    if phone_str or vpa_str:
        targets.append((phone_str, vpa_str))
    # Bulk: each entry in phones[] gets its own dossier
    for p in phones_arr:
        targets.append((p, None))
    # Bulk: each entry in vpas[] gets its own dossier
    for v in vpas_arr:
        targets.append((None, v))
    return targets


# ---------------------------------------------------------------------------
# Apify Actor entrypoint
# ---------------------------------------------------------------------------
async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}
        depth = actor_input.get("depth", "tier1")
        rz_key_id = actor_input.get("razorpayKeyId") or DEFAULT_RAZORPAY_KEY_ID
        payu_key = actor_input.get("payuKey") or DEFAULT_PAYU_KEY
        payu_salt = actor_input.get("payuSalt") or DEFAULT_PAYU_SALT

        targets = collect_targets(actor_input)
        if not targets:
            await Actor.fail(status_message="No targets — provide phone, vpa, phones[], or vpas[]")
            return

        Actor.log.info(f"UPI OSINT batch — {len(targets)} target(s), depth={depth}")
        if not rz_key_id:
            Actor.log.warning("No Razorpay key_id (input or env) — enumeration phase skipped")
        if not (payu_key and payu_salt):
            Actor.log.warning("No PayU key/salt (input or env) — full-name phase skipped")

        for i, (phone, vpa) in enumerate(targets, 1):
            Actor.log.info(f"[{i}/{len(targets)}] phone={phone!r}, vpa={vpa!r}")
            try:
                dossier = await build_dossier(phone, vpa, depth, rz_key_id, payu_key, payu_salt)
            except Exception as e:
                Actor.log.exception(f"target {i} build failed")
                dossier = {
                    "input_phone": phone, "input_vpa": vpa,
                    "queried_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                    "sources": [], "primary_name": None, "alternate_names": [], "confidence": 0.0,
                    "vpa_count": 0, "psp_primary": None, "phone_valid": False,
                    "phone": {}, "vpas": [], "app_usage_profile": {"primary": None, "all": [], "not_used": []},
                    "warnings": [], "errors": [f"build_dossier failed: {e}"],
                }
            active = sum(1 for v in dossier["vpas"] if v["is_active"])
            Actor.log.info(
                f"  → primary_name={dossier['primary_name']!r} confidence={dossier['confidence']} active_vpas={active}"
            )
            await Actor.push_data(dossier)


if __name__ == "__main__":
    asyncio.run(main())
