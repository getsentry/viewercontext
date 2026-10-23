from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Generator

from sentry_viewercontext.model import ViewerContext

# Owned here so shared clients (HTTP, RPC, tasks) can propagate the current viewer
# without importing service code.
viewer_context_var: contextvars.ContextVar[ViewerContext | None] = contextvars.ContextVar(
    "viewer_context", default=None
)


def get_viewer_context() -> ViewerContext | None:
    return viewer_context_var.get()


@contextlib.contextmanager
def viewer_context_scope(ctx: ViewerContext | None) -> Generator[None]:
    """Enter *ctx* for the block and restore the previous context on exit, even on error."""
    token = viewer_context_var.set(ctx)
    try:
        yield
    finally:
        viewer_context_var.reset(token)
