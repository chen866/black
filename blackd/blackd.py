import asyncio
import logging
import os
from concurrent.futures import Executor, ProcessPoolExecutor
from datetime import datetime, timezone
from functools import partial
from multiprocessing import freeze_support
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable, Set, Tuple, TypeVar

import black
import click
import isort
from _black_version import version as __version__
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import StreamResponse
from black.concurrency import maybe_install_uvloop

# middlewares.py start
if TYPE_CHECKING:
    F = TypeVar("F", bound=Callable[..., Any])
    middleware: Callable[[F], F]
else:
    try:
        from aiohttp.web_middlewares import middleware
    except ImportError:
        # @middleware is deprecated and its behaviour is the default since aiohttp 4.0
        # so if it doesn't exist anymore, define a no-op for forward compatibility.
        middleware = lambda x: x  # noqa: E731

Handler = Callable[[Request], Awaitable[StreamResponse]]
Middleware = Callable[[Request, Handler], Awaitable[StreamResponse]]


def cors(allow_headers: Iterable[str]) -> Middleware:
    @middleware
    async def impl(request: Request, handler: Handler) -> StreamResponse:
        is_options = request.method == "OPTIONS"
        is_preflight = is_options and "Access-Control-Request-Method" in request.headers
        if is_preflight:
            resp = StreamResponse()
        else:
            resp = await handler(request)

        origin = request.headers.get("Origin")
        if not origin:
            return resp

        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Expose-Headers"] = "*"
        if is_options:
            resp.headers["Access-Control-Allow-Headers"] = ", ".join(allow_headers)
            resp.headers["Access-Control-Allow-Methods"] = ", ".join(("OPTIONS", "POST"))

        return resp

    return impl


# middlewares.py end

# This is used internally by tests to shut down the server prematurely
_stop_signal = asyncio.Event()

# Request headers
PROTOCOL_VERSION_HEADER = "X-Protocol-Version"
LINE_LENGTH_HEADER = "X-Line-Length"
PYTHON_VARIANT_HEADER = "X-Python-Variant"
SKIP_SOURCE_FIRST_LINE = "X-Skip-Source-First-Line"
SKIP_STRING_NORMALIZATION_HEADER = "X-Skip-String-Normalization"
SKIP_MAGIC_TRAILING_COMMA = "X-Skip-Magic-Trailing-Comma"
PREVIEW = "X-Preview"
FAST_OR_SAFE_HEADER = "X-Fast-Or-Safe"
DIFF_HEADER = "X-Diff"

BLACK_HEADERS = [
    PROTOCOL_VERSION_HEADER,
    LINE_LENGTH_HEADER,
    PYTHON_VARIANT_HEADER,
    SKIP_SOURCE_FIRST_LINE,
    SKIP_STRING_NORMALIZATION_HEADER,
    SKIP_MAGIC_TRAILING_COMMA,
    PREVIEW,
    FAST_OR_SAFE_HEADER,
    DIFF_HEADER,
]

# Response headers
BLACK_VERSION_HEADER = "X-Black-Version"


class InvalidVariantHeader(Exception):
    pass


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--bind-host",
    type=str,
    help="Address to bind the server to.",
    default="0.0.0.0",
    show_default=True,
)
@click.option("--bind-port", type=int, help="Port to listen on", default=45484, show_default=True)
@click.version_option(version=black.__version__)
def main(bind_host: str, bind_port: int) -> None:
    app = make_app()
    ver = black.__version__
    black.out(f"blackd version {ver} listening on {bind_host} port {bind_port}")
    web.run_app(app, host=bind_host, port=bind_port, handle_signals=True, print=None)


def make_app() -> web.Application:
    app = web.Application(middlewares=[cors(allow_headers=(*BLACK_HEADERS, "Content-Type"))])
    executor = ProcessPoolExecutor()
    app.add_routes([web.post("/", partial(handle, executor=executor))])
    return app


async def handle(request: web.Request, executor: Executor) -> web.Response:
    headers = {BLACK_VERSION_HEADER: __version__}
    try:
        if request.headers.get(PROTOCOL_VERSION_HEADER, "1") != "1":
            return web.Response(status=501, text="This server only supports protocol version 1")
        try:
            line_length = int(request.headers.get(LINE_LENGTH_HEADER, black.DEFAULT_LINE_LENGTH))
        except ValueError:
            return web.Response(status=400, text="Invalid line length header value")

        if PYTHON_VARIANT_HEADER in request.headers:
            value = request.headers[PYTHON_VARIANT_HEADER]
            try:
                pyi, versions = parse_python_variant_header(value)
            except InvalidVariantHeader as e:
                return web.Response(
                    status=400,
                    text=f"Invalid value for {PYTHON_VARIANT_HEADER}: {e.args[0]}",
                )
        else:
            pyi = False
            versions = set()

        skip_string_normalization = bool(request.headers.get(SKIP_STRING_NORMALIZATION_HEADER, False))
        skip_magic_trailing_comma = bool(request.headers.get(SKIP_MAGIC_TRAILING_COMMA, False))
        skip_source_first_line = bool(request.headers.get(SKIP_SOURCE_FIRST_LINE, False))
        preview = bool(request.headers.get(PREVIEW, False))
        fast = False
        if request.headers.get(FAST_OR_SAFE_HEADER, "safe") == "fast":
            fast = True
        mode = black.FileMode(
            target_versions=versions,
            is_pyi=pyi,
            line_length=line_length,
            skip_source_first_line=skip_source_first_line,
            string_normalization=not skip_string_normalization,
            magic_trailing_comma=not skip_magic_trailing_comma,
            preview=preview,
        )
        req_bytes = await request.content.read()
        charset = request.charset if request.charset is not None else "utf8"
        req_str = req_bytes.decode(charset)
        then = datetime.now(timezone.utc)

        header = ""
        if skip_source_first_line:
            first_newline_position: int = req_str.find("\n") + 1
            header = req_str[:first_newline_position]
            req_str = req_str[first_newline_position:]

        req_str = isort.code(
            req_str,
            line_length=line_length,
            **isort_config,
        )

        loop = asyncio.get_event_loop()
        formatted_str = await loop.run_in_executor(
            executor, partial(black.format_file_contents, req_str, fast=fast, mode=mode)
        )

        # Preserve CRLF line endings
        nl = req_str.find("\n")
        if nl > 0 and req_str[nl - 1] == "\r":
            formatted_str = formatted_str.replace("\n", "\r\n")
            # If, after swapping line endings, nothing changed, then say so
            if formatted_str == req_str:
                raise black.NothingChanged

        # Put the source first line back
        req_str = header + req_str
        formatted_str = header + formatted_str

        # Only output the diff in the HTTP response
        only_diff = bool(request.headers.get(DIFF_HEADER, False))
        if only_diff:
            now = datetime.now(timezone.utc)
            src_name = f"In\t{then}"
            dst_name = f"Out\t{now}"
            loop = asyncio.get_event_loop()
            formatted_str = await loop.run_in_executor(
                executor,
                partial(black.diff, req_str, formatted_str, src_name, dst_name),
            )

        return web.Response(
            content_type=request.content_type,
            charset=charset,
            headers=headers,
            text=formatted_str,
        )
    except black.NothingChanged:
        return web.Response(status=204, headers=headers)
    except black.InvalidInput as e:
        return web.Response(status=400, headers=headers, text=str(e))
    except Exception as e:
        logging.exception("Exception during handling a request")
        return web.Response(status=500, headers=headers, text=str(e))


def parse_python_variant_header(value: str) -> Tuple[bool, Set[black.TargetVersion]]:
    if value == "pyi":
        return True, set()
    else:
        versions = set()
        for version in value.split(","):
            if version.startswith("py"):
                version = version[len("py") :]
            if "." in version:
                major_str, *rest = version.split(".")
            else:
                major_str = version[0]
                rest = [version[1:]] if len(version) > 1 else []
            try:
                major = int(major_str)
                if major not in (2, 3):
                    raise InvalidVariantHeader("major version must be 2 or 3")
                if len(rest) > 0:
                    minor = int(rest[0])
                    if major == 2:
                        raise InvalidVariantHeader("Python 2 is not supported")
                else:
                    # Default to lowest supported minor version.
                    minor = 7 if major == 2 else 3
                version_str = f"PY{major}{minor}"
                if major == 3 and not hasattr(black.TargetVersion, version_str):
                    raise InvalidVariantHeader(f"3.{minor} is not supported")
                versions.add(black.TargetVersion[version_str])
            except (KeyError, ValueError):
                raise InvalidVariantHeader("expected e.g. '3.7', 'py3.5'") from None
        return False, versions


def patched_main() -> None:
    maybe_install_uvloop()
    freeze_support()
    main()


logging.basicConfig(level=logging.DEBUG)

# known_first_party config
fp = "./known_first_party"
known_first_party = []
if os.path.exists(fp):
    with open(fp, "r") as f:
        known_first_party = [s.strip() for s in f.read().splitlines()]

known_first_party = [s for s in known_first_party if s and not s.startswith("#")]
logging.info(f"known_first_party: {known_first_party}")


# https://pycqa.github.io/isort/docs/configuration/options.html
isort_config = dict(
    multi_line_output=3,
    known_first_party=known_first_party,
    include_trailing_comma=True,
)


def run():
    patched_main()


if __name__ == "__main__":
    run()
    """
    usage:
    pip install black isort aiohttp
    python blackd.py
    install the pycharm plugin BlackConnect 
    """
