"""LMS curriculum, competency analytics, and identity provider service."""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from cyberlab.db.models import User, Competency, UserCompetency, Submission, Challenge

logger = logging.getLogger("cyberlab.lms")

STANDARD_COMPETENCIES = [
    {"id": "soc_investigation", "name": "SOC & Log Investigation", "description": "Analyzing authentication, firewall, and endpoint event logs to uncover intrusions."},
    {"id": "incident_response", "name": "Host Incident Response", "description": "Forensics timeline reconstruction, Linux/Windows artifact triage, and persistence hunting."},
    {"id": "network_analysis", "name": "Network & Email Forensics", "description": "Inspecting network traffic, packet captures, DNS queries, and phishing artifacts."},
    {"id": "web_security", "name": "Web Application Security", "description": "Auditing and exploiting OWASP Top 10 vulnerabilities including SQLi, XSS, and IDOR in isolated targets."},
    {"id": "threat_hunting", "name": "Enterprise Threat Hunting", "description": "Proactive hypothesis-driven hunting using Sysmon, parent-child process telemetry, and LotL detection."},
]

STANDARD_CURRICULUM = {
    "course_id": "cyber-ops-101",
    "course_name": "Cybersecurity Operations & Threat Defense",
    "description": "Hands-on browser-based realistic security investigation scenarios.",
    "modules": [
        {
            "id": "mod-soc",
            "title": "Module 1: SOC Fundamentals & Authentication Triage",
            "description": "Master log aggregation, brute force detection, and anomalous authentication analysis.",
            "lessons": [
                {
                    "id": "les-soc-1",
                    "title": "Lesson 1.1: Authentication Telemetry & Spray Attacks",
                    "challenge_id": "01-soc-auth-investigation",
                }
            ],
        },
        {
            "id": "mod-dfir-phish",
            "title": "Module 2: Email Security & Phishing Analysis",
            "description": "Dissect RFC 822 email headers, SPF/DKIM/DMARC, weaponized attachments, and C2 indicators.",
            "lessons": [
                {
                    "id": "les-phish-1",
                    "title": "Lesson 2.1: Header Forensics and Malware Attachment Extraction",
                    "challenge_id": "02-phishing-dfir",
                }
            ],
        },
        {
            "id": "mod-ir",
            "title": "Module 3: Host Incident Response & Linux Forensics",
            "description": "Reconstruct attack chains from bash history, system logs, and backdoor persistence mechanisms.",
            "lessons": [
                {
                    "id": "les-ir-1",
                    "title": "Lesson 3.1: Compromised Linux Server Timeline Reconstruction",
                    "challenge_id": "03-compromised-linux-server",
                }
            ],
        },
        {
            "id": "mod-web",
            "title": "Module 4: Web Application Vulnerabilities",
            "description": "Hands-on testing and exploitation of SQL injection and authorization bypasses in isolated sandboxes.",
            "lessons": [
                {
                    "id": "les-web-1",
                    "title": "Lesson 4.1: Exploiting SQL Injection & IDOR in Web Applications",
                    "challenge_id": "04-vulnerable-web-app",
                }
            ],
        },
        {
            "id": "mod-hunt",
            "title": "Module 5: Threat Hunting & Living-off-the-Land",
            "description": "Detect subtle adversary tactics using Sysmon parent-child trees and DNS entropy calculations.",
            "lessons": [
                {
                    "id": "les-hunt-1",
                    "title": "Lesson 5.1: Advanced Threat Hunt: Operation CloudSnoop",
                    "challenge_id": "05-threat-hunting-lotl",
                }
            ],
        },
    ],
}


class LMSService:
    """Manages curriculum mapping, competency scoring, and LMS sync."""

    @staticmethod
    def seed_competencies(db: Session):
        """Seed foundational competencies if they don't exist."""
        for comp in STANDARD_COMPETENCIES:
            existing = db.query(Competency).filter(Competency.id == comp["id"]).first()
            if not existing:
                c = Competency(id=comp["id"], name=comp["name"], description=comp["description"])
                db.add(c)
        db.commit()

    @staticmethod
    def get_or_create_student(db: Session, lms_user_id: str, username: str, email: str, role: str = "student") -> User:
        user = db.query(User).filter(User.lms_user_id == lms_user_id).first()
        if not user:
            user = User(
                lms_user_id=lms_user_id,
                username=username,
                email=email,
                role=role,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

            # Initialize competency scores
            for comp in STANDARD_COMPETENCIES:
                uc = UserCompetency(
                    user_id=user.id,
                    competency_id=comp["id"],
                    score_pct=0.0,
                    challenges_completed=0,
                )
                db.add(uc)
            db.commit()
        return user

    @staticmethod
    def get_curriculum(db: Session, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Return curriculum tree enriched with user progress if user_id is provided."""
        curriculum = dict(STANDARD_CURRICULUM)
        solved_challenges = set()
        if user_id:
            solved = db.query(Submission.challenge_id).filter(
                Submission.user_id == user_id,
                Submission.is_correct == True
            ).distinct().all()
            solved_challenges = {s[0] for s in solved}

        modules_copy = []
        total_challenges = 0
        completed_challenges = 0

        for mod in curriculum["modules"]:
            mod_copy = dict(mod)
            lessons_copy = []
            for les in mod["lessons"]:
                les_copy = dict(les)
                cid = les["challenge_id"]
                chal = db.query(Challenge).filter(Challenge.id == cid).first()
                total_challenges += 1
                is_solved = cid in solved_challenges
                if is_solved:
                    completed_challenges += 1

                les_copy["status"] = "completed" if is_solved else "available"
                les_copy["points"] = chal.points if chal else 100
                les_copy["difficulty"] = chal.difficulty if chal else "Beginner"
                lessons_copy.append(les_copy)
            mod_copy["lessons"] = lessons_copy
            modules_copy.append(mod_copy)

        curriculum["modules"] = modules_copy
        curriculum["total_challenges"] = total_challenges
        curriculum["completed_challenges"] = completed_challenges
        curriculum["progress_pct"] = round((completed_challenges / total_challenges * 100), 1) if total_challenges else 0
        return curriculum

    @staticmethod
    def update_student_competency(db: Session, user_id: str, challenge_id: str):
        """Recalculate competencies after a successful challenge submission."""
        chal = db.query(Challenge).filter(Challenge.id == challenge_id).first()
        if not chal or not chal.competency_id:
            return

        comp_id = chal.competency_id

        # Get all challenges mapped to this competency
        total_in_comp = db.query(Challenge).filter(
            Challenge.competency_id == comp_id,
            Challenge.enabled == True
        ).count()
        if total_in_comp == 0:
            total_in_comp = 1

        # Count completed challenges in this competency
        solved_in_comp = db.query(Submission.challenge_id).join(Challenge, Challenge.id == Submission.challenge_id).filter(
            Submission.user_id == user_id,
            Submission.is_correct == True,
            Challenge.competency_id == comp_id
        ).distinct().count()

        proficiency = min(100.0, round((solved_in_comp / total_in_comp) * 100.0, 1))

        uc = db.query(UserCompetency).filter(
            UserCompetency.user_id == user_id,
            UserCompetency.competency_id == comp_id
        ).first()

        if not uc:
            uc = UserCompetency(
                user_id=user_id,
                competency_id=comp_id,
                score_pct=proficiency,
                challenges_completed=solved_in_comp,
                last_updated_at=datetime.utcnow(),
            )
            db.add(uc)
        else:
            uc.score_pct = proficiency
            uc.challenges_completed = solved_in_comp
            uc.last_updated_at = datetime.utcnow()

        db.commit()

    @staticmethod
    def get_student_competency_matrix(db: Session, user_id: str) -> List[Dict[str, Any]]:
        """Return student competency breakdown."""
        competencies = db.query(Competency).all()
        user_comps = {uc.competency_id: uc for uc in db.query(UserCompetency).filter(UserCompetency.user_id == user_id).all()}

        results = []
        for comp in competencies:
            uc = user_comps.get(comp.id)
            results.append({
                "competency_id": comp.id,
                "name": comp.name,
                "description": comp.description,
                "score_pct": uc.score_pct if uc else 0.0,
                "challenges_completed": uc.challenges_completed if uc else 0,
            })
        return results

    @staticmethod
    def get_class_analytics(db: Session) -> Dict[str, Any]:
        """Aggregate class-level statistics for instructors."""
        competencies = db.query(Competency).all()
        class_comps = []

        total_students = db.query(User).filter(User.role == "student").count()

        for comp in competencies:
            user_scores = db.query(UserCompetency.score_pct).filter(
                UserCompetency.competency_id == comp.id
            ).all()
            avg_score = round(sum(s[0] for s in user_scores) / len(user_scores), 1) if user_scores else 0.0
            class_comps.append({
                "competency_id": comp.id,
                "name": comp.name,
                "average_score_pct": avg_score,
            })

        # Challenge success rates & attempts
        challenges = db.query(Challenge).filter(Challenge.enabled == True).all()
        challenge_stats = []
        for chal in challenges:
            total_subs = db.query(Submission).filter(Submission.challenge_id == chal.id).count()
            successful_subs = db.query(Submission).filter(
                Submission.challenge_id == chal.id,
                Submission.is_correct == True
            ).count()
            success_rate = round((successful_subs / total_subs * 100), 1) if total_subs > 0 else 0.0
            challenge_stats.append({
                "challenge_id": chal.id,
                "title": chal.title,
                "category": chal.category,
                "difficulty": chal.difficulty,
                "total_attempts": total_subs,
                "successful_solves": successful_subs,
                "success_rate_pct": success_rate,
            })

        return {
            "total_students": total_students,
            "class_competency_averages": class_comps,
            "challenge_stats": challenge_stats,
        }


lms_service = LMSService()

