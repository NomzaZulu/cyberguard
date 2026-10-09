import os

import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, List, Optional

from digital_impersonation.digital_impersonation_service import (
    analyze_digital_impersonation
)


app = FastAPI(
    title="CyberGuard Digital Impersonation API"
)


# ============================================================
# CORS
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

class DigitalImpersonationRequest(BaseModel):

    messages: List[Dict[str, Any]]
    organisation: Optional[str] = None
    organisation_domain: Optional[str] = None


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
@app.get("/api/digital_impersonation")
def health_check():

    return {
        "success": True,
        "service": "CyberGuard Digital Impersonation Detection",
        "status": "online",
        "detectors": 6
    }


# ============================================================
# DIGITAL IMPERSONATION ANALYSIS
# ============================================================

@app.post("/")
@app.post("/api/digital_impersonation")
def analyze_digital_impersonation_api(
    request: DigitalImpersonationRequest
):

    if not request.messages:

        raise HTTPException(
            status_code=400,
            detail="No impersonation messages supplied."
        )

    if len(request.messages) > 5000:
        raise HTTPException(status_code=413, detail="Maximum 5000 messages are supported per analysis.")

    for message in request.messages:
        if len(str(message)) > 30000:
            raise HTTPException(status_code=413, detail="A message record exceeds the supported size limit.")

    try:

        # ----------------------------------------------------
        # Convert frontend JSON array into a DataFrame
        # ----------------------------------------------------

        messages_df = pd.DataFrame(
            request.messages
        )


        # ----------------------------------------------------
        # Run the CyberGuard impersonation engine
        # ----------------------------------------------------

        result = analyze_digital_impersonation(
            messages=messages_df,
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
            "type": "digital_impersonation",
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
            "Digital Impersonation API error:",
            repr(error)
        )

        raise HTTPException(
            status_code=500,
            detail="Digital impersonation analysis failed."
        )
