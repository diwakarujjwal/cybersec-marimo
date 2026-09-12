"""API routes for procedural CTF challenge generation from lecture transcripts."""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from pathlib import Path

from cyberlab.core.config import settings
from cyberlab.api.deps import get_current_user
from cyberlab.db.models import User
from cyberlab.services.generator.llm_pipeline import transcript_generator
from cyberlab.services.generator.templates import list_templates

router = APIRouter(prefix="/api/generator", tags=["Generator"])


class TranscriptGenerateRequest(BaseModel):
    transcript: str = Field(
        ..., min_length=20, description="Video/lecture transcript text"
    )
    student_id: Optional[str] = Field(
        None, description="Optional student ID to seed unique randomization"
    )
    sync_to_ctfd: bool = Field(
        True, description="Whether to register challenge & hints in CTFd"
    )


class TemplateInfoResponse(BaseModel):
    id: str
    title: str
    category: str
    difficulty: str
    competency_id: str


@router.get("/templates", response_model=List[TemplateInfoResponse])
def get_available_templates():
    """List all human-authored challenge templates available in the library."""
    return list_templates()


@router.post("/from-transcript")
async def generate_challenge_from_transcript(
    req: TranscriptGenerateRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Ingest a video transcript, extract learning objectives, select matching template,
    fill slots via LLM, synthesize randomized sandbox artifacts, and register locked
    hints with CTFd.
    """
    try:
        output_base = settings.CHALLENGES_DIR
        seed = req.student_id or current_user.id
        result = await transcript_generator.generate_and_deploy(
            transcript_text=req.transcript,
            output_dir=output_base,
            student_id=seed,
            sync_to_ctfd=req.sync_to_ctfd,
        )
        return {
            "status": "success",
            "message": f"Successfully generated and deployed challenge: {result['title']}",
            "challenge": result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Challenge generation failed: {e}")
