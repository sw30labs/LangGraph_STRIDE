#!/usr/bin/env python3
"""OpenAI-compatible stub server for ultraport contract tests. Stdlib only.

Stands in for the real backends so ported apps can be exercised end-to-end in
any sandbox, in both platform personas:

  --persona vllm   DGX Spark stand-in. Serves a pinned NVIDIA-style model id.
  --persona omlx   Apple Silicon stand-in. Serves an MLX-style model id and,
                   unless the request disables thinking via
                   chat_template_kwargs.enable_thinking=false, prefixes the
                   answer with a <think>...</think> block — exactly the
                   reasoning-model behavior that forces ports to implement
                   strip_thinking correctly.

Also serves /admin/dashboard (200, HTML) so URL-normalization code paths
("user pasted the dashboard URL") can be probed, and /v1/models for model
discovery. Deterministic responses embed a marker plus a digest of the last
user message so tests can assert the plumbing without a real model.

Usage:
  python mock_inference_server.py --persona vllm --port 8000
  MOCK_PERSONA=omlx python mock_inference_server.py
"""

import argparse
import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PERSONAS = {
    "vllm": {"models": ["nvidia/Qwen3.6-27B-NVFP4"], "thinking": False},
    "omlx": {"models": ["Qwen3.6-27B-bf16"], "thinking": True},
}

MARKER = "MOCK-INFERENCE"


def _content_to_text_and_images(content):
    """OpenAI content is a string or a list of typed parts."""
    if isinstance(content, str):
        return content, 0
    text, images = [], 0
    for part in content or []:
        kind = part.get("type")
        if kind == "text":
            text.append(part.get("text", ""))
        elif kind == "image_url":
            images += 1
    return " ".join(text), images


def _thinking_disabled(payload):
    kwargs = payload.get("chat_template_kwargs") or {}
    return kwargs.get("enable_thinking") is False


class Handler(BaseHTTPRequestHandler):
    persona = "vllm"

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # quiet by default
        if os.environ.get("MOCK_VERBOSE"):
            super().log_message(fmt, *args)

    def do_GET(self):
        cfg = PERSONAS[self.persona]
        if self.path.rstrip("/") == "/v1/models":
            data = [{"id": m, "object": "model", "owned_by": self.persona} for m in cfg["models"]]
            self._send_json({"object": "list", "data": data})
        elif self.path.startswith("/admin/dashboard"):
            body = b"<html><body>mock dashboard</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.rstrip("/") in ("", "/v1"):
            self._send_json({"status": "ok", "persona": self.persona})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._send_json({"error": "bad json"}, 400)
            return

        cfg = PERSONAS[self.persona]
        messages = payload.get("messages", [])
        last_user = ""
        images = 0
        for msg in messages:
            if msg.get("role") == "user":
                last_user, n = _content_to_text_and_images(msg.get("content"))
                images += n

        digest = hashlib.sha256(last_user.encode()).hexdigest()[:12]
        vision_note = f" images={images}" if images else ""
        answer = f"{MARKER} persona={self.persona} digest={digest}{vision_note}"

        if cfg["thinking"] and not _thinking_disabled(payload):
            answer = f"<think>mock deliberation about {digest}</think>{answer}"

        max_tokens = payload.get("max_tokens")
        finish = "stop"
        # Crude truncation emulation so finish_reason=length guards are testable.
        if isinstance(max_tokens, int) and max_tokens < 8:
            answer = answer[: max_tokens * 4]
            finish = "length"

        self._send_json(
            {
                "id": f"chatcmpl-mock-{digest}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": payload.get("model") or cfg["models"][0],
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": answer},
                        "finish_reason": finish,
                    }
                ],
                "usage": {
                    "prompt_tokens": max(1, len(last_user) // 4),
                    "completion_tokens": max(1, len(answer) // 4),
                    "total_tokens": max(2, (len(last_user) + len(answer)) // 4),
                },
            }
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--persona",
        choices=sorted(PERSONAS),
        default=os.environ.get("MOCK_PERSONA", "vllm"),
    )
    parser.add_argument("--port", type=int, default=int(os.environ.get("MOCK_PORT", "8000")))
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    Handler.persona = args.persona
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"[mock-inference] persona={args.persona} on http://{args.host}:{args.port}/v1", flush=True
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
