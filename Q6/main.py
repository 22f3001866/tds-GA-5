"""MCP server exposing the solve_challenge tool."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from challenge import challenge_response_from_headers
from mcp.server import FastMCP
from mcp.server.fastmcp.server import Context

mcp = FastMCP(
    "ga5-mcp-server",
    stateless_http=True,
    json_response=True,
    streamable_http_path="/mcp",
    host="0.0.0.0",
)


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@mcp.custom_route("/", methods=["GET"])
async def root(_request: Request) -> JSONResponse:
    return JSONResponse({"service": "mcp", "status": "ok"})


@mcp.tool(name="solve_challenge")
async def solve_challenge(ctx: Context) -> str:
    request = ctx.request_context.request
    if request is not None and isinstance(request, Request):
        return challenge_response_from_headers(request.headers)

    raise ValueError("Missing X-Exam-Challenge header.")


app = mcp.streamable_http_app()
