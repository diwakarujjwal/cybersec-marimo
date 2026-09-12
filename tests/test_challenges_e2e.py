"""End-to-End integration tests for all 5 sample challenge scenarios."""
import asyncio
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberlab.db.database import Base
from cyberlab.db.models import User, Challenge, Submission
from cyberlab.services.challenge_loader import challenge_loader
from cyberlab.services.lms_service import lms_service
from cyberlab.services.ctfd_client import ctfd_client


def test_all_five_challenges_discovery_and_sync():
    async def run():
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        e2e_db = TestingSessionLocal()
        try:
            lms_service.seed_competencies(e2e_db)

            challenges_dir = Path(__file__).parent.parent / "challenges"
            discovered = challenge_loader.discover_all(challenges_dir)

            # 1. Verify all 5 challenges are discovered
            assert len(discovered) == 5
            discovered_ids = {d["manifest"].id for d in discovered}
            expected_ids = {
                "01-soc-auth-investigation",
                "02-phishing-dfir",
                "03-compromised-linux-server",
                "04-vulnerable-web-app",
                "05-threat-hunting-lotl",
            }
            assert expected_ids.issubset(discovered_ids)

            # 2. Sync to DB & CTFd
            count = await challenge_loader.sync_to_db_and_ctfd(e2e_db, challenges_dir)
            assert count == 5

            # 3. Create student
            student = lms_service.get_or_create_student(
                e2e_db,
                lms_user_id="alice-test-1",
                username="alice",
                email="alice@cyberlab.edu",
            )

            # 4. Verify each challenge can be submitted with valid flag and updates competencies
            expected_flags = {
                "01-soc-auth-investigation": "FLAG{brute_force_pivot_admin_2026}",
                "02-phishing-dfir": "FLAG{dmarc_fail_invoice_c2_domain_detected}",
                "03-compromised-linux-server": "FLAG{crontab_reverse_shell_persisted_victim}",
                "04-vulnerable-web-app": "FLAG{sqli_union_payroll_leak_pwned}",
                "05-threat-hunting-lotl": "FLAG{dns_tunneling_data_exfil_uncovered}",
            }

            for chal_id, correct_flag in expected_flags.items():
                chal = e2e_db.query(Challenge).filter(Challenge.id == chal_id).first()
                assert chal is not None, f"Challenge {chal_id} missing in DB"
                assert chal.flag == correct_flag

                # Submit flag to CTFd
                is_correct, points, msg = await ctfd_client.submit_flag(
                    challenge_id=chal_id,
                    submitted_flag=correct_flag,
                    user_id=student.id,
                    expected_flag=chal.flag,
                    points=chal.points,
                )
                assert is_correct is True, f"Submission failed for {chal_id}"
                assert points == chal.points

                # Record submission and update competency
                sub = Submission(
                    user_id=student.id,
                    challenge_id=chal_id,
                    submitted_flag=correct_flag,
                    is_correct=True,
                    points_awarded=points,
                )
                e2e_db.add(sub)
                e2e_db.commit()

                lms_service.update_student_competency(e2e_db, student.id, chal_id)

            # 5. Verify student competencies after completing all 5 challenges
            comps = lms_service.get_student_competency_matrix(e2e_db, student.id)
            for c in comps:
                assert c["score_pct"] == 100.0, f"Competency {c['competency_id']} not at 100%"
                assert c["challenges_completed"] >= 1
        finally:
            e2e_db.close()

    asyncio.run(run())

