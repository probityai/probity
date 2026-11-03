"""One-file repro: LangGraph's RetryPolicy re-sends a write whose reply arrived.

Run with langgraph 1.2.19 and httpx installed:  python repro_langgraph_sibling_retry.py

A ToolNode step holds two tool calls. `create_order` posts a write and gets its reply. `notify`
loses its connection once. RetryPolicy retries the whole node, so `create_order` posts again.
Expected output: orders_received=2 for one requested order.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import RetryPolicy

orders = []
notify_calls = []


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.path == "/orders":
            orders.append(1)
            body = b'{"ok": true}'
        else:
            notify_calls.append(1)
            if len(notify_calls) == 1:
                self.connection.close()  # the connection is lost before any reply
                return
            body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{server.server_port}"


@tool
def create_order(sku: str) -> str:
    """Create an order."""
    httpx.post(url + "/orders", json={"sku": sku}, timeout=5.0).raise_for_status()
    return "confirmed"


@tool
def notify(message: str) -> str:
    """Notify the customer."""
    httpx.post(url + "/notify", json={"message": message}, timeout=5.0).raise_for_status()
    return "sent"


graph = StateGraph(MessagesState)
graph.add_node("tools", ToolNode([create_order, notify]), retry_policy=RetryPolicy(max_attempts=3, initial_interval=0.01))
graph.add_edge(START, "tools")
graph.add_edge("tools", END)
app = graph.compile()

call = AIMessage(
    content="",
    tool_calls=[
        {"name": "create_order", "args": {"sku": "A-1"}, "id": "c1"},
        {"name": "notify", "args": {"message": "ordered"}, "id": "c2"},
    ],
)
app.invoke({"messages": [call]})
print(f"orders_received={len(orders)} (one order was requested)")
