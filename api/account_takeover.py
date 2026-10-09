import os

import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

from account_takeover.account_takeover_service import (
    analyze_account_takeover
)


app = FastAPI(
    title="CyberGuard Account Takeover API"
)


# ============================================================
# CORS
# ============================================================
#
# The frontend is commonly served from a different origin than
# this API (e.g. static hosting plus a serverless backend).
# Without CORS the browser blocks every analysis request.
# ============================================================

_allowed_origins = [
    origin.strip()
    for origin in os.getenv("CYBERGUARD_ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


# ============================================================
# REQUEST MODEL
# ============================================================

class AccountTakeoverRequest(BaseModel):

    events: List[Dict[str, Any]]

    profiles: Optional[
        List[Dict[str, Any]]
    ] = None

    organisation: Optional[str] = None
    organisation_domain: Optional[str] = None


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
@app.get("/api/account_takeover")
def health_check():

    return {
        "success": True,
        "service": "CyberGuard Account Takeover Detection",
        "status": "online",
        "detectors": 6
    }


# ============================================================
# ACCOUNT TAKEOVER ANALYSIS
# ============================================================

@app.post("/")
@app.post("/api/account_takeover")
def analyze_account_takeover_api(
    request: AccountTakeoverRequest
):

    if not request.events:

        raise HTTPException(
            status_code=400,
            detail="No event telemetry supplied."
        )

    # Defensive API limits prevent oversized telemetry payloads from
    # exhausting a serverless function or creating accidental memory pressure.
    if len(request.events) > 5000:
        raise HTTPException(status_code=413, detail="Maximum 5000 telemetry events are supported per analysis.")

    if request.profiles is not None and len(request.profiles) > 5000:
        raise HTTPException(status_code=413, detail="Maximum 5000 user profiles are supported per analysis.")

    for event in request.events:
        if len(str(event)) > 20000:
            raise HTTPException(status_code=413, detail="A telemetry record exceeds the supported size limit.")

    try:

        # ----------------------------------------------------
        # Convert frontend JSON arrays into DataFrames
        # ----------------------------------------------------

        events_df = pd.DataFrame(
            request.events
        )


        if request.profiles:

            profiles_df = pd.DataFrame(
                request.profiles
            )

        else:

            profiles_df = None


        # ----------------------------------------------------
        # Run the existing CyberGuard engine
        # ----------------------------------------------------

        result = analyze_account_takeover(
            events=events_df,
            profiles=profiles_df,
            organisation=request.organisation,
            organisation_domain=request.organisation_domain
        )


        # ----------------------------------------------------
        # Convert pandas / timestamps / numpy values
        # into JSON-safe values
        # ----------------------------------------------------

        def make_json_safe(value):

            if isinstance(
                value,
                dict
            ):

                return {
                    str(key):
                    make_json_safe(val)

                    for key, val
                    in value.items()
                }


            if isinstance(
                value,
                list
            ):

                return [
                    make_json_safe(item)
                    for item in value
                ]


            if isinstance(
                value,
                tuple
            ):

                return [
                    make_json_safe(item)
                    for item in value
                ]


            if isinstance(
                value,
                pd.Timestamp
            ):

                return value.isoformat()


            try:

                if pd.isna(value):

                    return None

            except Exception:

                pass


            if hasattr(
                value,
                "item"
            ):

                try:

                    return value.item()

                except Exception:

                    pass


            return value


        return {
            "success": True,
            "type": "account_takeover",
            "result": make_json_safe(result)
        }


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


    except TypeError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


    except Exception as error:

        print(
            "Account Takeover API error:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail="Account takeover analysis failed."
        )
