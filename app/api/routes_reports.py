from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.services.report_service import build_lab_report, generate_markdown_report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/findings.json")
def get_json_report():
    report = build_lab_report()
    return JSONResponse(content=report.model_dump(mode="json"))


@router.get("/findings.md")
def get_markdown_report():
    from fastapi.responses import PlainTextResponse
    report = build_lab_report()
    return PlainTextResponse(content=generate_markdown_report(report))
