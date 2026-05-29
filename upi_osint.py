#!/usr/bin/env python3
"""UPI ID OSINT — phone number to UPI VPAs + bank-registered names.

Direct and accurate. No guessing. UPI-specific only.

Pipeline:
  1. Phone format validation (libphonenumber)                     → confirm valid Indian mobile
  2. Razorpay frontend /v1/payments/validate/account?key_id=...   → phone → active VPAs (FREE)
  3. PayU /merchant/postservice?form=2  validateVPA               → VPA → full unmasked name from NPCI
  4. PSP/Bank inference from NPCI handle taxonomy                 → authoritative, deterministic
  5. App usage profile (derived from active VPAs)                 → no guessing, pure derivation
  6. Multi-VPA name agreement → confidence score

What this actor does NOT do (sibling actors will):
  - Phone presence on WhatsApp/Telegram/Signal (separate actor)
  - GSTN/MCA business records (separate actor)
  - LeakOSINT breach correlation (separate actor)
  - Truecaller-alternative name lookup (separate actor)

Usage:
  export RAZORPAY_KEY_ID="rzp_live_..."
  export PAYU_KEY="..."
  export PAYU_SALT="..."
  python upi_osint.py +91XXXXXXXXXX
  python upi_osint.py +91XXXXXXXXXX --json out.json --no-banner
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Any

import ssl

import aiohttp
import certifi

_SSL_CTX = ssl.create_default_context(cafile=certifi.where())

# ---------------------------------------------------------------------------
# Handle taxonomy — 30 most-used Indian UPI handles, ordered by hit-probability
# ---------------------------------------------------------------------------
HANDLES: dict[str, dict[str, str]] = {
    "ybl":         {"psp": "PhonePe",       "bank": "Yes Bank",         "tier": 1},
    "ibl":         {"psp": "PhonePe",       "bank": "IndusInd Bank",    "tier": 1},
    "axl":         {"psp": "PhonePe",       "bank": "Axis Bank",        "tier": 1},
    "oksbi":       {"psp": "Google Pay",    "bank": "SBI",              "tier": 1},
    "okhdfcbank":  {"psp": "Google Pay",    "bank": "HDFC",             "tier": 1},
    "okicici":     {"psp": "Google Pay",    "bank": "ICICI",            "tier": 1},
    "okaxis":      {"psp": "Google Pay",    "bank": "Axis Bank",        "tier": 1},
    "paytm":       {"psp": "Paytm",         "bank": "Paytm Bank (legacy)", "tier": 1},
    "ptyes":       {"psp": "Paytm",         "bank": "Yes Bank",         "tier": 1},
    "ptaxis":      {"psp": "Paytm",         "bank": "Axis Bank",        "tier": 1},
    "ptsbi":       {"psp": "Paytm",         "bank": "SBI",              "tier": 1},
    "pthdfc":      {"psp": "Paytm",         "bank": "HDFC",             "tier": 1},
    "upi":         {"psp": "BHIM",          "bank": "NPCI direct",      "tier": 1},
    "apl":         {"psp": "Amazon Pay",    "bank": "Axis Bank",        "tier": 2},
    "yapl":        {"psp": "Amazon Pay",    "bank": "Yes Bank",         "tier": 2},
    "rapl":        {"psp": "Amazon Pay",    "bank": "RBL Bank",         "tier": 2},
    "waicici":     {"psp": "WhatsApp Pay",  "bank": "ICICI",            "tier": 2},
    "waaxis":      {"psp": "WhatsApp Pay",  "bank": "Axis Bank",        "tier": 2},
    "wahdfcbank":  {"psp": "WhatsApp Pay",  "bank": "HDFC",             "tier": 2},
    "wasbi":       {"psp": "WhatsApp Pay",  "bank": "SBI",              "tier": 2},
    "sbi":         {"psp": "SBI Pay",       "bank": "SBI",              "tier": 3},
    "icici":       {"psp": "iMobile Pay",   "bank": "ICICI",            "tier": 3},
    "hdfcbank":    {"psp": "HDFC Pay",      "bank": "HDFC",             "tier": 3},
    "axisbank":    {"psp": "Axis Pay",      "bank": "Axis Bank",        "tier": 3},
    "kotak":       {"psp": "Kotak 811",     "bank": "Kotak",            "tier": 3},
    "cred":        {"psp": "Cred",          "bank": "Axis (sponsoring)", "tier": 3},
    "fam":         {"psp": "FamPay",        "bank": "IDFC First",       "tier": 3},
    "slice":       {"psp": "Slice",         "bank": "Sponsoring",       "tier": 3},
    "jio":         {"psp": "MyJio",         "bank": "Jio Payments",     "tier": 3},
    "airtel":      {"psp": "Airtel Pay",    "bank": "Airtel Payments",  "tier": 3},
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class VpaResult:
    vpa: str
    handle: str
    psp: str
    bank: str
    is_active: bool
    masked_name: str | None = None
    full_name: str | None = None
    razorpay_status: str | None = None
    payu_status: str | None = None
    error: str | None = None


@dataclass
class PhoneInfo:
    """Phone format validation only. Does NOT claim carrier/operator (unreliable due to MNP)."""
    country: str | None = None
    region: str | None = None
    line_type: str | None = None
    valid: bool = False
    e164: str | None = None
    national: str | None = None


@dataclass
class Dossier:
    input_phone: str
    queried_at: str
    sources: list[str]
    primary_name: str | None = None
    alternate_names: list[str] = field(default_factory=list)
    confidence: float = 0.0
    phone: PhoneInfo = field(default_factory=PhoneInfo)
    vpas: list[VpaResult] = field(default_factory=list)
    app_usage_profile: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Razorpay frontend enumerator — needs only key_id, no secret
# ---------------------------------------------------------------------------
async def razorpay_validate(session: aiohttp.ClientSession, key_id: str, vpa: str) -> dict[str, Any]:
    url = f"https://api.razorpay.com/v1/payments/validate/account?key_id={key_id}"
    try:
        async with session.post(url, json={"entity": "vpa", "value": vpa}, timeout=aiohttp.ClientTimeout(total=10)) as r:
            return await r.json(content_type=None)
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# PayU validateVPA — returns full unmasked name from NPCI
# ---------------------------------------------------------------------------
def payu_hash(key: str, salt: str, vpa: str) -> str:
    return hashlib.sha512(f"{key}|validateVPA|{vpa}|{salt}".encode()).hexdigest()


async def payu_validate(session: aiohttp.ClientSession, key: str, salt: str, vpa: str) -> dict[str, Any]:
    url = "https://secure.payu.in/merchant/postservice?form=2"
    data = {
        "key": key,
        "command": "validateVPA",
        "hash": payu_hash(key, salt, vpa),
        "var1": vpa,
    }
    try:
        async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=15)) as r:
            return await r.json(content_type=None)
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Phone format validation (offline, deterministic — libphonenumber)
# Does NOT claim carrier/operator (unreliable due to Mobile Number Portability in India).
# ---------------------------------------------------------------------------
def phone_info(phone_input: str) -> PhoneInfo:
    info = PhoneInfo()
    try:
        import phonenumbers
        from phonenumbers import geocoder, number_type
        pn = phonenumbers.parse(phone_input, "IN")
        info.valid = phonenumbers.is_valid_number(pn)
        info.country = phonenumbers.region_code_for_number(pn) or "IN"
        info.region = geocoder.description_for_number(pn, "en")
        nt = number_type(pn)
        info.line_type = {
            0: "fixed_line", 1: "mobile", 2: "fixed_or_mobile",
            3: "toll_free", 4: "premium_rate", 5: "shared_cost",
            6: "voip", 7: "personal", 8: "pager", 9: "uan",
            10: "voicemail", 27: "emergency",
        }.get(nt, "unknown")
        info.e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
        info.national = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
    except ImportError:
        pass
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Normalize phone input → variants
# ---------------------------------------------------------------------------
def normalize_phone(raw: str) -> tuple[str, str, str]:
    """Return (e164_with_plus, e164_no_plus, local_10digit)."""
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
    return f"+91{local}", f"91{local}", local


# ---------------------------------------------------------------------------
# Identity correlator — confidence scoring across multiple sources
# ---------------------------------------------------------------------------
def normalize_name(n: str) -> str:
    return re.sub(r"\s+", " ", n.strip()).upper()


def compute_confidence(vpas: list[VpaResult]) -> tuple[str | None, list[str], float]:
    names: dict[str, int] = {}
    for v in vpas:
        if v.full_name and v.full_name != "NA":
            names[normalize_name(v.full_name)] = names.get(normalize_name(v.full_name), 0) + 1
    if not names:
        return None, [], 0.0
    sorted_names = sorted(names.items(), key=lambda x: -x[1])
    primary, count = sorted_names[0]
    alternates = [n for n, _ in sorted_names[1:]]
    # confidence: 0.5 base for 1 source, +0.15 per agreeing source up to 1.0
    confidence = min(1.0, 0.5 + 0.15 * (count - 1))
    if len(sorted_names) > 1:
        confidence -= 0.1  # penalty for disagreement
    return primary, alternates, round(max(0.0, confidence), 2)


def app_usage_profile(vpas: list[VpaResult]) -> dict[str, Any]:
    psp_counts: dict[str, int] = {}
    for v in vpas:
        if v.is_active:
            psp_counts[v.psp] = psp_counts.get(v.psp, 0) + 1
    if not psp_counts:
        return {"primary": None, "all": [], "not_used": []}
    sorted_psps = sorted(psp_counts.items(), key=lambda x: -x[1])
    all_psps_in_taxonomy = {info["psp"] for info in HANDLES.values()}
    used_psps = set(psp_counts)
    return {
        "primary": sorted_psps[0][0],
        "all": [{"psp": p, "vpa_count": c} for p, c in sorted_psps],
        "not_used": sorted(all_psps_in_taxonomy - used_psps),
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
async def build_dossier(
    phone_input: str,
    razorpay_key_id: str | None,
    payu_key: str | None,
    payu_salt: str | None,
    depth: str = "tier1",
) -> Dossier:
    e164_plus, e164_no_plus, local10 = normalize_phone(phone_input)
    sources: list[str] = []
    dossier = Dossier(
        input_phone=e164_plus,
        queried_at=time.strftime("%Y-%m-%d %H:%M:%S IST", time.localtime()),
        sources=sources,
    )

    # Phone format validation (offline, instant)
    dossier.phone = phone_info(e164_plus)
    sources.append("libphonenumber")

    # Pick handle set by depth
    if depth == "tier1":
        handles = [h for h, m in HANDLES.items() if m["tier"] == 1]
    elif depth == "tier2":
        handles = [h for h, m in HANDLES.items() if m["tier"] <= 2]
    else:
        handles = list(HANDLES.keys())

    candidates = [f"{local10}@{h}" for h in handles]
    connector = aiohttp.TCPConnector(limit=20, ssl=_SSL_CTX)
    async with aiohttp.ClientSession(connector=connector) as session:
        # PHASE 1 — Razorpay enumeration (parallel)
        if razorpay_key_id:
            sources.append("razorpay_frontend")
            rz_tasks = [razorpay_validate(session, razorpay_key_id, v) for v in candidates]
            rz_results = await asyncio.gather(*rz_tasks)
        else:
            rz_results = [{"skipped": True}] * len(candidates)
            dossier.warnings.append("RAZORPAY_KEY_ID not set — skipped enumeration")

        # Build initial VpaResult records
        active_vpas: list[VpaResult] = []
        for handle, vpa, rz in zip(handles, candidates, rz_results):
            meta = HANDLES[handle]
            is_active = bool(rz.get("success") and rz.get("customer_name"))
            v = VpaResult(
                vpa=vpa,
                handle=handle,
                psp=meta["psp"],
                bank=meta["bank"],
                is_active=is_active,
                masked_name=rz.get("customer_name"),
                razorpay_status="active" if is_active else ("inactive" if rz.get("success") is False else "skipped"),
            )
            if is_active:
                active_vpas.append(v)
            dossier.vpas.append(v)

        # PHASE 2 — PayU name resolution for active VPAs (parallel)
        if active_vpas and payu_key and payu_salt:
            sources.append("payu_validateVPA")
            payu_tasks = [payu_validate(session, payu_key, payu_salt, v.vpa) for v in active_vpas]
            payu_results = await asyncio.gather(*payu_tasks)
            for v, pu in zip(active_vpas, payu_results):
                v.payu_status = pu.get("status")
                if pu.get("isVPAValid") == 1 and pu.get("payerAccountName"):
                    v.full_name = pu["payerAccountName"]
                elif pu.get("error"):
                    v.error = pu["error"]
        elif not (payu_key and payu_salt):
            dossier.warnings.append("PAYU_KEY/PAYU_SALT not set — skipped full-name resolution")

    # Confidence + correlation
    primary, alts, conf = compute_confidence(dossier.vpas)
    dossier.primary_name = primary
    dossier.alternate_names = alts
    dossier.confidence = conf
    dossier.app_usage_profile = app_usage_profile(dossier.vpas)

    return dossier


# ---------------------------------------------------------------------------
# Pretty-print dossier
# ---------------------------------------------------------------------------
def format_dossier(d: Dossier) -> str:
    out: list[str] = []
    bar = "═" * 76
    out.append("╔" + bar + "╗")
    out.append(f"║  UPI OSINT DOSSIER — {d.input_phone:<54}║")
    out.append(f"║  Generated: {d.queried_at:<63}║")
    sources_line = ", ".join(d.sources)
    out.append(f"║  Sources: {sources_line[:65]:<65}║")
    out.append("╚" + bar + "╝")
    out.append("")
    out.append("PRIMARY IDENTITY")
    if d.primary_name:
        out.append(f"  Name (high-confidence):    {d.primary_name}")
        if d.alternate_names:
            out.append(f"  Alternate spellings:        {', '.join(d.alternate_names)}")
        out.append(f"  Confidence:                 {d.confidence:.2f}")
    else:
        out.append("  Name:                       (not resolved — Razorpay masked only or no PayU key)")
    out.append("")

    active = [v for v in d.vpas if v.is_active]
    out.append(f"ACTIVE UPI VPAs ({len(active)} found)")
    if active:
        out.append("  ┌──────────────────────────┬─────────────────┬──────────────────┬─────────────────────┐")
        out.append("  │ VPA                      │ PSP             │ Bank             │ Registered Name     │")
        out.append("  ├──────────────────────────┼─────────────────┼──────────────────┼─────────────────────┤")
        for v in active:
            name = v.full_name or (v.masked_name + " (masked)" if v.masked_name else "?")
            out.append(f"  │ {v.vpa:<24} │ {v.psp:<15} │ {v.bank:<16} │ {name:<19} │")
        out.append("  └──────────────────────────┴─────────────────┴──────────────────┴─────────────────────┘")
    else:
        out.append("  (no active VPAs found)")
    out.append("")

    out.append("APP USAGE PROFILE")
    if d.app_usage_profile.get("primary"):
        out.append(f"  PRIMARY:   {d.app_usage_profile['primary']} ({len(active)} active VPA(s))")
        for entry in d.app_usage_profile.get("all", [])[1:]:
            out.append(f"  ALSO:      {entry['psp']} ({entry['vpa_count']} VPA)")
        not_used = d.app_usage_profile.get("not_used", [])
        if not_used:
            out.append(f"  NOT USED:  {', '.join(not_used[:8])}")
    else:
        out.append("  (no UPI apps detected)")
    out.append("")

    out.append("PHONE INPUT VALIDATION")
    c = d.phone
    out.append(f"  E164:        {c.e164 or '(parse failed)'}")
    out.append(f"  National:    {c.national or '?'}")
    out.append(f"  Country:     {c.country or '?'} ({c.region or '?'})")
    out.append(f"  Line type:   {c.line_type or '?'}")
    out.append(f"  Valid:       {c.valid}")
    out.append("")

    if d.warnings:
        out.append("WARNINGS")
        for w in d.warnings:
            out.append(f"  ⚠  {w}")
        out.append("")

    if d.errors:
        out.append("ERRORS")
        for e in d.errors:
            out.append(f"  ✗  {e}")
        out.append("")

    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="UPI OSINT Dossier")
    parser.add_argument("phone", help="Phone number (e.g. +91XXXXXXXXXX)")
    parser.add_argument("--depth", choices=["tier1", "tier2", "exhaustive"], default="tier1")
    parser.add_argument("--json", metavar="PATH", help="Write JSON dossier to file")
    parser.add_argument("--no-banner", action="store_true", help="Print only JSON, no pretty output")
    parser.add_argument("--razorpay-key-id", default=os.environ.get("RAZORPAY_KEY_ID"))
    parser.add_argument("--payu-key", default=os.environ.get("PAYU_KEY"))
    parser.add_argument("--payu-salt", default=os.environ.get("PAYU_SALT"))
    args = parser.parse_args()

    dossier = asyncio.run(
        build_dossier(
            phone_input=args.phone,
            razorpay_key_id=args.razorpay_key_id,
            payu_key=args.payu_key,
            payu_salt=args.payu_salt,
            depth=args.depth,
        )
    )

    # Serialize
    def encoder(o: Any) -> Any:
        if hasattr(o, "__dict__"):
            return o.__dict__
        return str(o)

    json_blob = json.dumps(asdict(dossier), indent=2, default=encoder)

    if args.json:
        with open(args.json, "w") as f:
            f.write(json_blob)

    if args.no_banner:
        print(json_blob)
    else:
        print(format_dossier(dossier))
        print()
        print("─" * 66)
        print(f"JSON dossier {'written to ' + args.json if args.json else '(use --json to save)'}")


if __name__ == "__main__":
    main()
