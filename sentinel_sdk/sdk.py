"""Compatibility shim for the Python SDK.

The canonical implementation lives in ``sdks/python/sentinel_sdk`` to keep the
SDKs grouped under the shared ``sdks/`` tree. This module preserves the
``import sentinel_sdk`` surface for users and integrations.
"""

from sdks.python.sentinel_sdk import sdk as _sdk

globals().update({name: getattr(_sdk, name) for name in dir(_sdk) if not name.startswith('__')})
