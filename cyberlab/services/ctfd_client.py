"""CTFd API integration client and local provider."""
import logging
import httpx
from typing import Dict, Any, List, Optional, Tuple
from cyberlab.core.config import settings
from cyberlab.core.security import timing_safe_flag_check

logger = logging.getLogger("cyberlab.ctfd")


class CTFdClient:
    """Client for CTFd REST API."""

    def __init__(self, base_url: str = "", api_token: str = ""):
        self.base_url = (base_url or settings.CTFD_URL).rstrip("/")
        self.api_token = api_token or settings.CTFD_API_TOKEN
        self.headers = {
            "Authorization": f"Token {self.api_token}",
            "Content-Type": "application/json",
        }
        # In-memory mock store for offline/standalone execution
        self._mock_challenges: Dict[str, Dict[str, Any]] = {}
        self._mock_submissions: List[Dict[str, Any]] = []
        self._mock_unlocked_hints: Dict[str, List[int]] = {}  # "user_id:chal_id" -> [hint_ids]

    async def check_connection(self) -> bool:
        """Check if remote CTFd instance is reachable."""
        if not self.api_token:
            return False
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.base_url}/api/v1/users/me", headers=self.headers)
                return res.status_code == 200
        except Exception:
            return False

    async def register_challenge(self, challenge: Dict[str, Any]) -> int:
        """
        Sync challenge to CTFd.
        Returns the CTFd numeric challenge ID.
        """
        chal_id = challenge["id"]
        if settings.ENABLE_EMBEDDED_CTFD_MOCK:
            mock_id = len(self._mock_challenges) + 1
            self._mock_challenges[chal_id] = {
                "ctfd_id": mock_id,
                "name": challenge["title"],
                "category": challenge["category"],
                "value": challenge["points"],
                "flag": challenge["flag"],
                "hints": challenge.get("hints", []),
            }
            return mock_id

        # Real CTFd HTTP request
        payload = {
            "name": challenge["title"],
            "category": challenge["category"],
            "description": challenge.get("scenario_md", ""),
            "value": challenge["points"],
            "state": "visible",
            "type": "standard",
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            res = await client.post(f"{self.base_url}/api/v1/challenges", json=payload, headers=self.headers)
            if res.status_code in (200, 201):
                data = res.json()
                real_id = data["data"]["id"]
                # Register flag
                flag_payload = {"challenge_id": real_id, "content": challenge["flag"], "type": "static"}
                await client.post(f"{self.base_url}/api/v1/flags", json=flag_payload, headers=self.headers)
                return real_id
            raise RuntimeError(f"Failed to register challenge with CTFd: {res.text}")

    async def submit_flag(
        self,
        challenge_id: str,
        submitted_flag: str,
        user_id: str,
        expected_flag: Optional[str] = None,
        points: int = 100,
    ) -> Tuple[bool, int, str]:
        """
        Validate submitted flag and return (is_correct, points_awarded, message).
        """
        submitted_flag = submitted_flag.strip()

        # Check against local / mock store if remote CTFd is offline
        target_flag = expected_flag
        chal_meta = self._mock_challenges.get(challenge_id)
        if chal_meta:
            target_flag = chal_meta.get("flag", target_flag)
            points = chal_meta.get("value", points)

        if not target_flag:
            return False, 0, "Challenge flag configuration missing."

        is_correct = timing_safe_flag_check(submitted_flag, target_flag)

        # Deduct penalties for unlocked hints
        hint_key = f"{user_id}:{challenge_id}"
        unlocked = self._mock_unlocked_hints.get(hint_key, [])
        penalty_total = 0
        if chal_meta:
            for h in chal_meta.get("hints", []):
                if h.get("id") in unlocked:
                    penalty_total += h.get("penalty", 0)

        final_points = max(0, points - penalty_total) if is_correct else 0

        self._mock_submissions.append({
            "user_id": user_id,
            "challenge_id": challenge_id,
            "flag": submitted_flag,
            "is_correct": is_correct,
            "points": final_points,
        })

        if is_correct:
            return True, final_points, f"Correct! You earned {final_points} points."
        return False, 0, "Incorrect flag. Review your evidence and try again."

    async def unlock_hint(
        self,
        challenge_id: str,
        hint_id: int,
        user_id: str,
        hints_list: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, str, int]:
        """
        Unlock a hint for a user, returning (success, hint_content, penalty).
        """
        hint_key = f"{user_id}:{challenge_id}"
        if hint_key not in self._mock_unlocked_hints:
            self._mock_unlocked_hints[hint_key] = []

        available_hints = hints_list or []
        if not available_hints and challenge_id in self._mock_challenges:
            available_hints = self._mock_challenges[challenge_id].get("hints", [])

        for h in available_hints:
            if h.get("id") == hint_id:
                if hint_id not in self._mock_unlocked_hints[hint_key]:
                    self._mock_unlocked_hints[hint_key].append(hint_id)
                return True, h.get("content", ""), h.get("penalty", 0)

        return False, "Hint not found", 0

    async def get_scoreboard(self) -> List[Dict[str, Any]]:
        """Get aggregate scores for all users."""
        user_scores: Dict[str, int] = {}
        for sub in self._mock_submissions:
            if sub["is_correct"]:
                user_id = sub["user_id"]
                user_scores[user_id] = user_scores.get(user_id, 0) + sub["points"]

        sorted_users = sorted(user_scores.items(), key=lambda x: x[1], reverse=True)
        return [{"rank": i + 1, "user_id": uid, "score": score} for i, (uid, score) in enumerate(sorted_users)]


ctfd_client = CTFdClient()

