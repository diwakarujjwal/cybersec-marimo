"""Tests verifying LMS curriculum mapping and independent competency tracking."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberlab.db.database import Base
from cyberlab.db.models import User, Challenge, Submission
from cyberlab.services.lms_service import lms_service


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        lms_service.seed_competencies(db)
        yield db
    finally:
        db.close()


def test_lms_curriculum_and_competency_update(test_db):
    # 1. Create student
    student = lms_service.get_or_create_student(
        test_db,
        lms_user_id="lms-stu-99",
        username="bob",
        email="bob@cyberlab.edu",
    )
    assert student.id is not None

    # 2. Check initial competency scores (should be 0%)
    comps = lms_service.get_student_competency_matrix(test_db, student.id)
    assert len(comps) == 5
    for c in comps:
        assert c["score_pct"] == 0.0

    # 3. Create a challenge tied to soc_investigation
    chal = Challenge(
        id="soc-lab-1",
        title="SOC Investigation Lab",
        category="SOC",
        competency_id="soc_investigation",
        flag="FLAG{test}",
        points=100,
        enabled=True,
    )
    test_db.add(chal)
    test_db.commit()

    # 4. Simulate correct submission
    sub = Submission(
        user_id=student.id,
        challenge_id="soc-lab-1",
        submitted_flag="FLAG{test}",
        is_correct=True,
        points_awarded=100,
    )
    test_db.add(sub)
    test_db.commit()

    # 5. Update competency
    lms_service.update_student_competency(test_db, student.id, "soc-lab-1")

    # 6. Verify competency has increased
    updated_comps = lms_service.get_student_competency_matrix(test_db, student.id)
    soc_comp = next((c for c in updated_comps if c["competency_id"] == "soc_investigation"), None)
    assert soc_comp is not None
    assert soc_comp["score_pct"] == 100.0
    assert soc_comp["challenges_completed"] == 1

