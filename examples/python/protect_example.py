import requests
import sentinel

sentinel.protect(base_url="http://127.0.0.1:8000", api_key="admin-demo-key", auto_instrument=True)

@sentinel.tool("list_files")
def list_files(path: str):
    return {"path": path, "entries": ["a.txt", "b.txt"]}

with sentinel.trace_agent("research-agent"):
    print(list_files("/tmp"))
    # This outbound call will be inspected if requests is installed.
    # requests.get("https://example.com")
