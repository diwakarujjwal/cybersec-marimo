"""Reverse proxy service for Marimo and vulnerable web app sessions."""

import httpx
import logging
from datetime import datetime
from fastapi import Request, Response, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse
import websockets
import asyncio

from cyberlab.db.database import SessionLocal
from cyberlab.db.models import ChallengeInstance

logger = logging.getLogger("cyberlab.proxy")


class SessionReverseProxy:
    """Proxies HTTP and WebSocket traffic securely to isolated student containers."""

    @staticmethod
    def _validate_session(session_id: str, token: str | None = None) -> dict:
        db = SessionLocal()
        try:
            query = db.query(ChallengeInstance).filter(
                ChallengeInstance.id == session_id,
                ChallengeInstance.status == "running",
            )
            if token:
                inst = query.filter(ChallengeInstance.proxy_token == token).first()
            else:
                inst = query.first()

            if not inst:
                raise HTTPException(
                    status_code=403, detail="Invalid or expired session token."
                )

            if inst.expires_at <= datetime.utcnow():
                inst.status = "expired"
                db.commit()
                raise HTTPException(
                    status_code=410, detail="Challenge session has expired."
                )

            # Refresh heartbeat
            inst.last_heartbeat_at = datetime.utcnow()
            target_port = inst.internal_port
            chal_id = inst.challenge_id
            env_type = inst.challenge.environment_type if inst.challenge else "marimo"
            status = inst.status
            proxy_token = inst.proxy_token
            db.commit()

            return {
                "id": session_id,
                "internal_port": target_port,
                "challenge_id": chal_id,
                "environment_type": env_type,
                "status": status,
                "proxy_token": proxy_token,
            }
        finally:
            db.close()

    @classmethod
    async def handle_http(
        cls, request: Request, session_id: str, path: str
    ) -> Response:
        """Proxy HTTP requests to the student's isolated instance port."""
        token = (
            request.query_params.get("token")
            or request.query_params.get("access_token")
            or request.headers.get("X-Session-Token")
            or request.cookies.get(f"token_{session_id}")
        )

        session_info = cls._validate_session(session_id, token)
        target_port = session_info["internal_port"]
        env_type = session_info.get("environment_type", "marimo")

        clean_path = path.lstrip("/")
        if env_type == "marimo":
            target_url = (
                f"http://127.0.0.1:{target_port}/session/{session_id}/{clean_path}"
                if clean_path
                else f"http://127.0.0.1:{target_port}/session/{session_id}/"
            )
        else:
            target_url = (
                f"http://127.0.0.1:{target_port}/{clean_path}"
                if clean_path
                else f"http://127.0.0.1:{target_port}/"
            )

        # Clean headers: do not forward internal authorization or secret cookies to container
        excluded_headers = {"host", "authorization", "content-length"}
        forward_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in excluded_headers
        }

        query_params = dict(request.query_params)

        body = await request.body()

        client = httpx.AsyncClient(timeout=30.0)
        try:
            req = client.build_request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                params=query_params,
                content=body,
            )
            res = await client.send(req, stream=True)

            async def stream_generator():
                try:
                    async for chunk in res.aiter_raw():
                        yield chunk
                finally:
                    await res.aclose()
                    await client.aclose()

            resp_headers = dict(res.headers)
            resp_headers.pop("content-length", None)
            resp_headers.pop("transfer-encoding", None)

            # Set cookie for seamless subsequent asset fetches
            response = StreamingResponse(
                stream_generator(),
                status_code=res.status_code,
                headers=resp_headers,
                media_type=res.headers.get("content-type"),
            )
            effective_token = token or session_info.get("proxy_token")
            if effective_token:
                response.set_cookie(
                    key=f"token_{session_id}",
                    value=effective_token,
                    path=f"/session/{session_id}",
                    httponly=True,
                    samesite="lax",
                )
            return response

        except Exception as e:
            await client.aclose()
            logger.error(f"Error proxying HTTP request to port {target_port}: {e}")
            raise HTTPException(
                status_code=502, detail="Unable to connect to challenge container."
            )

    @classmethod
    async def handle_websocket(cls, websocket: WebSocket, session_id: str, path: str):
        """Proxy WebSocket traffic (crucial for Marimo reactive kernel communication)."""
        token = (
            websocket.query_params.get("token")
            or websocket.query_params.get("access_token")
            or websocket.cookies.get(f"token_{session_id}")
        )

        try:
            session_info = cls._validate_session(session_id, token)
        except HTTPException:
            await websocket.close(code=1008)
            return
        except Exception:
            await websocket.close(code=1011)
            return

        target_port = session_info["internal_port"]
        env_type = session_info.get("environment_type", "marimo")

        clean_path = path.strip("/")
        if env_type == "marimo":
            target_ws_url = (
                f"ws://127.0.0.1:{target_port}/session/{session_id}/{clean_path}"
                if clean_path
                else f"ws://127.0.0.1:{target_port}/session/{session_id}/ws"
            )
        else:
            target_ws_url = (
                f"ws://127.0.0.1:{target_port}/{clean_path}"
                if clean_path
                else f"ws://127.0.0.1:{target_port}/"
            )

        if websocket.query_params:
            target_ws_url = f"{target_ws_url}?{websocket.query_params}"

        target_ws = None
        try:
            subprotocols = [
                s for s in websocket.scope.get("subprotocols", []) if s
            ] or None
            target_ws = await websockets.connect(
                target_ws_url,
                max_size=16 * 1024 * 1024,
                subprotocols=subprotocols,
                proxy=None,
            )
        except Exception as e:
            logger.error(f"Failed to connect to target WS at {target_ws_url}: {e}")
            await websocket.close(code=1011)
            return

        try:
            await websocket.accept(subprotocol=target_ws.subprotocol)
        except Exception as e:
            logger.warning(f"Failed to accept client WS: {e}")
            await target_ws.close()
            return

        async def client_to_target():
            try:
                while True:
                    data = await websocket.receive()
                    msg_type = data.get("type")
                    if msg_type == "websocket.disconnect":
                        break
                    if "text" in data and data["text"] is not None:
                        await target_ws.send(data["text"])
                    elif "bytes" in data and data["bytes"] is not None:
                        await target_ws.send(data["bytes"])
            except (WebSocketDisconnect, asyncio.CancelledError):
                pass
            except Exception as e:
                logger.debug(f"client_to_target error: {e}")

        async def target_to_client():
            try:
                async for message in target_ws:
                    if isinstance(message, str):
                        await websocket.send_text(message)
                    else:
                        await websocket.send_bytes(message)
            except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
                pass
            except Exception as e:
                logger.debug(f"target_to_client error: {e}")

        t_client = asyncio.create_task(client_to_target())
        t_target = asyncio.create_task(target_to_client())

        try:
            done, pending = await asyncio.wait(
                [t_client, t_target],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        except Exception as e:
            logger.warning(f"WebSocket proxy error: {e}")
        finally:
            try:
                await target_ws.close()
            except Exception:
                pass
            try:
                await websocket.close()
            except Exception:
                pass


proxy_service = SessionReverseProxy()
