from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from opensearchpy import OpenSearch, OpenSearchException, RequestError

from manifest_cli_tool.sbom_parser import ParsedSBOM


class OpenSearchClientError(Exception):
    """Raised when an OpenSearch operation fails."""


# ---------------------------------------------------------------------------
# Indices
# ---------------------------------------------------------------------------

_ORIGINALS_INDEX = "originals"
_PROCESSED_INDEX = "processed"

_ORIGINALS_MAPPING = {
    "mappings": {
        "properties": {
            "filename": {"type": "keyword"},
            "content": {"type": "text", "index": False},
        }
    }
}

_PROCESSED_MAPPING = {
    "mappings": {
        "properties": {
            "filename": {"type": "keyword"},
            "format": {"type": "keyword"},
            "serial_number": {"type": "keyword"},
            "metadata": {
                "properties": {
                    "tool": {"type": "keyword"},
                    "authors": {"type": "keyword"},
                    "timestamp": {"type": "date", "ignore_malformed": True},
                    "component": {"type": "keyword"},
                }
            },
            "components": {
                "type": "nested",
                "properties": {
                    "name": {"type": "keyword"},
                    "version": {"type": "keyword"},
                    "purl": {"type": "keyword"},
                    "cpe": {"type": "keyword"},
                    "licenses": {"type": "keyword"},
                    "supplier": {"type": "keyword"},
                },
            },
        }
    }
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_client() -> OpenSearch:
    host = os.environ.get("OPENSEARCH_HOST", "localhost")
    port = int(os.environ.get("OPENSEARCH_PORT", 9200))

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        use_ssl=False,
    )


def _ensure_index(client: OpenSearch, index: str, mapping: dict) -> None:
    try:
        client.indices.create(index=index, body=mapping, ignore=400)
    except OpenSearchException as exc:
        raise OpenSearchClientError(f"Failed to create '{index}' index: {exc}") from exc


def _index_doc(client: OpenSearch, index: str, doc_id: str, body: dict) -> str:
    try:
        response = client.index(index=index, id=doc_id, body=body, refresh="wait_for")
    except RequestError as exc:
        raise OpenSearchClientError(f"Failed to index document '{doc_id}' into '{index}': {exc}") from exc
    except OpenSearchException as exc:
        raise OpenSearchClientError(f"OpenSearch error indexing '{doc_id}' into '{index}': {exc}") from exc
    return response["_id"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def upload_original(file_path: str) -> str:
    """Upload raw file contents to the 'originals' index.

    The document ID is the file's base name. Returns the document ID on success.
    """
    path = Path(file_path)
    doc_id = path.name

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise OpenSearchClientError(f"Cannot read '{file_path}': {exc}") from exc

    client = _build_client()
    _ensure_index(client, _ORIGINALS_INDEX, _ORIGINALS_MAPPING)
    return _index_doc(client, _ORIGINALS_INDEX, doc_id, {"filename": doc_id, "content": raw})


def index_processed(sbom: ParsedSBOM, file_path: str) -> str:
    """Index a parsed SBOM into the 'processed' index.

    The document ID is the file's base name. Returns the document ID on success.
    """
    doc_id = Path(file_path).name

    document: dict[str, Any] = {
        "filename": doc_id,
        "format": sbom.format.value,
        "serial_number": sbom.serial_number,
        "metadata": {
            "tool": sbom.metadata.tool,
            "authors": sbom.metadata.authors,
            "timestamp": sbom.metadata.timestamp,
            "component": sbom.metadata.component,
        },
        "components": [
            {
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
                "cpe": c.cpe,
                "licenses": c.licenses,
                "supplier": c.supplier,
            }
            for c in sbom.components
        ],
    }

    client = _build_client()
    _ensure_index(client, _PROCESSED_INDEX, _PROCESSED_MAPPING)
    return _index_doc(client, _PROCESSED_INDEX, doc_id, document)


def query_components(
    name: str | None = None,
    version: str | None = None,
    license: str | None = None,
) -> list[dict]:
    """Return all processed SBOM documents whose components match all provided filters.

    All supplied filters are ANDed together on the same component.
    """
    must_clauses: list[dict] = []
    if name:
        must_clauses.append({"term": {"components.name": name}})
    if version:
        must_clauses.append({"term": {"components.version": version}})
    if license:
        must_clauses.append({"term": {"components.licenses": license}})

    query = {
        "query": {
            "nested": {
                "path": "components",
                "query": {"bool": {"must": must_clauses}},
                "inner_hits": {},
            }
        }
    }

    return _run_query(_PROCESSED_INDEX, query)


def _run_query(index: str, query: dict) -> list[dict]:
    client = _build_client()
    try:
        response = client.search(index=index, body=query)
    except OpenSearchException as exc:
        raise OpenSearchClientError(f"Query against '{index}' failed: {exc}") from exc

    results = []
    for hit in response["hits"]["hits"]:
        results.append({
            "filename": hit["_source"].get("filename"),
            "format": hit["_source"].get("format"),
            "serial_number": hit["_source"].get("serial_number"),
            "matched_components": [
                ih["_source"]
                for ih in hit.get("inner_hits", {}).get("components", {}).get("hits", {}).get("hits", [])
            ],
        })
    return results
