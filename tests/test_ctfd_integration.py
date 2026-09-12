"""Tests verifying CTFd integration, flag verification, and hint deductions."""
import asyncio
from cyberlab.services.ctfd_client import CTFdClient


def test_ctfd_flag_verification_and_scoring():
    async def run():
        client = CTFdClient()

        # Register challenge
        chal_data = {
            "id": "test-incident",
            "title": "Test Incident",
            "category": "SOC",
            "points": 100,
            "flag": "FLAG{valid_test_flag_123}",
            "hints": [
                {"id": 1, "content": "Look at the IP", "penalty": 15},
                {"id": 2, "content": "Look at the timestamp", "penalty": 20},
            ],
        }
        ctfd_id = await client.register_challenge(chal_data)
        assert ctfd_id > 0

        # 1. Test incorrect flag submission
        is_correct, points, msg = await client.submit_flag(
            challenge_id="test-incident",
            submitted_flag="FLAG{wrong_flag}",
            user_id="student-1",
            expected_flag="FLAG{valid_test_flag_123}",
            points=100,
        )
        assert is_correct is False
        assert points == 0

        # 2. Test unlock hint with penalty deduction
        success, hint_text, penalty = await client.unlock_hint(
            challenge_id="test-incident",
            hint_id=1,
            user_id="student-1",
        )
        assert success is True
        assert hint_text == "Look at the IP"
        assert penalty == 15

        # 3. Test correct flag submission after hint unlocked
        is_correct, points, msg = await client.submit_flag(
            challenge_id="test-incident",
            submitted_flag="FLAG{valid_test_flag_123}",
            user_id="student-1",
            expected_flag="FLAG{valid_test_flag_123}",
            points=100,
        )
        assert is_correct is True
        # 100 points - 15 penalty = 85 points
        assert points == 85

        # 4. Verify Scoreboard
        scoreboard = await client.get_scoreboard()
        assert len(scoreboard) > 0
        assert scoreboard[0]["user_id"] == "student-1"
        assert scoreboard[0]["score"] == 85

    asyncio.run(run())

