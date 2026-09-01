"""STUB. Owned by branch ``foundation/browser-app``. Do NOT edit on other branches.

Real implementation: FastAPI bound to 127.0.0.1, ``POST /api/scan`` with
Pydantic request/response models calling ``scan.scan``, ``GET /`` serving
``server/static/index.html``. Path confined to the given root.
"""
from __future__ import annotations


def create_app():
    from fastapi import FastAPI

    return FastAPI(title="security-preview")
