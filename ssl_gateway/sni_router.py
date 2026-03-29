"""
SNI context router: maintains a per-domain SSLContext and switches based on SNI.
"""
import logging
import ssl
from ssl_gateway.cert_store import has_cert, load_ssl_context

logger = logging.getLogger(__name__)

# domain → SSLContext cache
_contexts: dict[str, ssl.SSLContext] = {}


def get_context(fqdn: str) -> ssl.SSLContext | None:
    if fqdn in _contexts:
        return _contexts[fqdn]
    if has_cert(fqdn):
        try:
            ctx = load_ssl_context(fqdn)
            _contexts[fqdn] = ctx
            return ctx
        except Exception as e:
            logger.error("Failed to load SSL context for %s: %s", fqdn, e)
    return None


def reload_context(fqdn: str) -> None:
    """Force-reload the SSLContext for a domain (called after cert renewal)."""
    _contexts.pop(fqdn, None)
    get_context(fqdn)
    logger.info("SSL context reloaded for %s", fqdn)


def build_sni_callback(default_context: ssl.SSLContext):
    """Return an SNI callback that switches contexts per domain."""
    def sni_callback(ssl_object, server_name, original_context):
        if server_name:
            ctx = get_context(server_name)
            if ctx:
                ssl_object.context = ctx
                return
        # Fall back to default context (self-signed / no cert yet)
    return sni_callback
