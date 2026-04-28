import asyncio
import hashlib
import os
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse

CS_API_URL        = os.getenv("CS_API_URL", "https://api.colourswift.com").rstrip("/")
VPS_AUTH_SECRET   = os.getenv("VPS_AUTH_SECRET", "").strip()
POLL_INTERVAL     = int(os.getenv("POLL_INTERVAL", "30"))

HASH_API_URL      = "https://efkou1u21ooih2hko.colourswift.com/check_batch"
HASH_API_KEY      = "23JVO3ojo23oO3O423rrTR"
HASH_TIMEOUT      = 8.0
DOWNLOAD_TIMEOUT  = 60.0

app = FastAPI(title="SafeHaven Scanner")


async def check_hashes(hashes: list[str]) -> dict[str, Any]:
    if not hashes:
        return {"verdict": "not_checked", "matches": [], "note": "No hashes supplied"}

    normalised = []
    seen: set[str] = set()
    for h in hashes:
        if not isinstance(h, str):
            continue
        v = h.strip().lower()
        if not v or v in seen:
            continue
        seen.add(v)
        normalised.append(v)

    if not normalised:
        return {"verdict": "not_checked", "matches": [], "note": "No valid hashes after normalisation"}

    try:
        async with httpx.AsyncClient(timeout=HASH_TIMEOUT) as http:
            response = await http.post(
                HASH_API_URL,
                headers={"Content-Type": "application/json", "x-cs-key": HASH_API_KEY},
                json=normalised,
            )
        response.raise_for_status()
        data = response.json()

        if not isinstance(data, dict):
            return {"verdict": "unknown", "matches": [], "note": "Unexpected response shape from hash API"}

        found = data.get("found", [])
        if not isinstance(found, list):
            found = []

        found_normalised = []
        found_seen: set[str] = set()
        for h in found:
            if not isinstance(h, str):
                continue
            v = h.strip().lower()
            if not v or v in found_seen:
                continue
            found_seen.add(v)
            found_normalised.append(v)

        if found_normalised:
            return {
                "verdict": "known_malware",
                "matches": [{"hash": h, "label": "known malware hash match"} for h in found_normalised],
            }

        return {"verdict": "clean", "matches": []}

    except httpx.TimeoutException:
        return {"verdict": "unknown", "matches": [], "note": "Hash check timed out"}
    except Exception as exc:
        return {"verdict": "unknown", "matches": [], "note": f"Hash check error: {exc}"}


async def download_apk(url: str) -> bytes:
    async with httpx.AsyncClient(timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as http:
        response = await http.get(url)
        response.raise_for_status()
        return response.content


async def post_scan_result(submission_id: str, result: dict[str, Any]) -> None:
    async with httpx.AsyncClient(timeout=15.0) as http:
        response = await http.post(
            f"{CS_API_URL}/internal/store/scan-result",
            headers={
                "Content-Type": "application/json",
                "x-vps-auth": VPS_AUTH_SECRET,
            },
            json={"submissionId": submission_id, **result},
        )
        response.raise_for_status()


async def process_submission(submission: dict[str, Any]) -> None:
    submission_id  = submission.get("id", "")
    download_url   = submission.get("downloadUrl", "")
    package_name   = submission.get("package_name", "")
    version_code   = submission.get("version_code", "")

    if not submission_id or not download_url:
        print(f"[scanner] skipping submission with missing id or downloadUrl: {submission_id}")
        return

    print(f"[scanner] processing {package_name}@{version_code} ({submission_id})")

    try:
        apk_bytes = await download_apk(download_url)
    except Exception as exc:
        print(f"[scanner] download failed for {submission_id}: {exc}")
        await post_scan_result(submission_id, {
            "passed":  False,
            "detail":  {"error": "download_failed", "note": str(exc)},
        })
        return

    sha256   = hashlib.sha256(apk_bytes).hexdigest()
    apk_size = len(apk_bytes)

    print(f"[scanner] sha256={sha256} size={apk_size} for {submission_id}")

    hash_result = await check_hashes([sha256])

    verdict = hash_result.get("verdict", "unknown")
    passed  = verdict != "known_malware"

    print(f"[scanner] verdict={verdict} passed={passed} for {submission_id}")

    await post_scan_result(submission_id, {
        "passed":    passed,
        "detail":    hash_result,
        "apkSha256": sha256,
        "apkSize":   apk_size,
    })

    print(f"[scanner] result posted for {submission_id}")


async def fetch_pending_scans() -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=15.0) as http:
        response = await http.get(
            f"{CS_API_URL}/internal/store/pending-scans",
            headers={"x-vps-auth": VPS_AUTH_SECRET},
        )
        response.raise_for_status()
        data = response.json()
        return data.get("submissions", [])


async def poll_loop() -> None:
    print(f"[scanner] poll loop started — interval={POLL_INTERVAL}s")
    while True:
        try:
            submissions = await fetch_pending_scans()
            if submissions:
                print(f"[scanner] {len(submissions)} pending scan(s)")
                for submission in submissions:
                    try:
                        await process_submission(submission)
                    except Exception as exc:
                        print(f"[scanner] error processing {submission.get('id')}: {exc}")
        except Exception as exc:
            print(f"[scanner] poll error: {exc}")

        await asyncio.sleep(POLL_INTERVAL)


@app.on_event("startup")
async def startup() -> None:
    if not VPS_AUTH_SECRET:
        raise RuntimeError("VPS_AUTH_SECRET is not set")
    asyncio.create_task(poll_loop())


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "ok":           True,
        "hash_api_url": HASH_API_URL,
        "api_url":      CS_API_URL,
        "poll_interval": POLL_INTERVAL,
    }
