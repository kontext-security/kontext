#!/usr/bin/env python3
"""Loopback stand-in for the Kontext API and a fake model in the self-serve E2E.

- Answers the install-token ping so `kontext setup` can bind, and accepts every
  other Kontext request so the daemon runs.
- Plays a model for Claude Code (ANTHROPIC_BASE_URL): the first turn asks for
  one Bash call (tool_use id toolu_e2e_<n>), the turn after the tool result
  ends. No real model or account is used."""
import itertools, json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

calls = itertools.count(1)

class Handler(BaseHTTPRequestHandler):
    def _reply(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        print("GET", self.path, flush=True)
        if self.path.startswith("/api/v1/authorization-ledger/ping"):
            return self._reply({"organization_id": "org_e2e", "organization_name": "Kontext E2E"})
        if self.path.startswith("/v1/"):
            return self._reply({"data": [], "has_more": False})
        self._reply({})

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        print("POST", self.path, flush=True)
        if self.path.startswith("/v1/messages/count_tokens"):
            return self._reply({"input_tokens": 10})
        if self.path.startswith("/v1/messages"):
            return self._model(json.loads(body or b"{}"))
        self._reply({})

    def _model(self, request):
        if '"tool_result"' in json.dumps(request.get("messages", [])):
            reason, block = "end_turn", {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": "Done."}
        else:
            n = next(calls)
            reason, block = "tool_use", {"type": "tool_use", "id": f"toolu_e2e_{n}", "name": "Bash", "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps({"command": f"echo kontext-e2e-{n}", "description": "E2E probe"})}
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for event in [
            {"type": "message_start", "message": {"id": "msg_e2e", "type": "message", "role": "assistant", "model": "claude-sonnet-4-5", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 0}}},
            {"type": "content_block_start", "index": 0, "content_block": block},
            {"type": "content_block_delta", "index": 0, "delta": delta},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": None}, "usage": {"output_tokens": 5}},
            {"type": "message_stop"},
        ]:
            self.wfile.write(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode())
        self.wfile.flush()

    def log_message(self, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
