"""Approved local MCP companion: public metadata, no account or file access."""
from __future__ import annotations
import json
import httpx2
from mcp.server import MCPServer
from pydantic import BaseModel

PACKAGES=frozenset({"requests","httpx","fastapi"})
REPOSITORIES=frozenset({"python/cpython","pallets/flask","fastapi/fastapi"})

def read_package(package: str):
    if package not in PACKAGES:
        raise ValueError("Package not approved")
    with httpx2.Client(trust_env=False,follow_redirects=False,timeout=5) as client:
        with client.stream("GET","https://pypi.org/pypi/"+package+"/json") as response:
            response.raise_for_status()
            data=bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk[:2097153-len(data)])
                if len(data)>2097152:
                    raise ValueError("Oversized package metadata")
    payload=json.loads(data)
    info=payload["info"]
    if info["name"].lower()!=package:
        raise ValueError("Package identity mismatch")
    version=info["version"]
    if not isinstance(version,str) or not 1<=len(version)<=80:
        raise ValueError("Invalid package version")
    return {"status":"completed","package":package,"version":version}

class PackageResult(BaseModel):
    status: str
    package: str
    version: str

class RepositoryResult(BaseModel):
    status: str
    repository: str
    stars: int
    forks: int
    default_branch: str

def create_companion():
    server=MCPServer("Shadow Hunter public metadata companion")

    @server.tool(structured_output=True)
    def public_package(package: str) -> PackageResult:
        """Get the published version of an approved public Python package."""
        return PackageResult(**read_package(package))

    @server.tool(structured_output=True)
    def public_repository(repository: str) -> RepositoryResult:
        """Read metadata from an explicitly approved public GitHub repository."""
        if repository not in REPOSITORIES:
            raise ValueError("Repository not approved")
        from .scheduler import public_repo_metadata
        return RepositoryResult(**public_repo_metadata(repository))

    app=server.streamable_http_app(streamable_http_path="/mcp",stateless_http=True,json_response=True,
                                   max_request_body_size=8192)
    return server,app

def main():
    import uvicorn
    server,app=create_companion()
    uvicorn.run(app,host="127.0.0.1",port=8766,access_log=False)

if __name__=="__main__":
    main()
