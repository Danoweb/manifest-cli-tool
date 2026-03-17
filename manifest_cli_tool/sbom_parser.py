from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SBOMError(Exception):
    """Base class for all SBOM errors."""


class SBOMParseError(SBOMError):
    """Raised when a file cannot be read or decoded."""


class SBOMValidationError(SBOMError):
    """Raised when required fields are missing or the format is unsupported."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class SBOMFormat(Enum):
    CYCLONEDX_1_6 = "CycloneDX 1.6"
    SPDX_3_0 = "SPDX 3.0"


@dataclass
class Component:
    name: str
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    licenses: list[str] = field(default_factory=list)
    supplier: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SBOMMetadata:
    tool: str | None = None
    authors: list[str] = field(default_factory=list)
    timestamp: str | None = None
    component: str | None = None  # top-level subject (the thing being described)


@dataclass
class ParsedSBOM:
    format: SBOMFormat
    serial_number: str | None
    metadata: SBOMMetadata
    components: list[Component]
    raw: dict[str, Any]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_CYCLONEDX_XML_NS = "http://cyclonedx.org/schema/bom/1.6"


class SBOMParser:
    """Reads and interprets CycloneDX 1.6 and SPDX 3.0 SBOM files.

    Supports JSON and XML encodings for CycloneDX; JSON-LD for SPDX 3.0.

    Usage::

        parser = SBOMParser()
        sbom = parser.parse("/path/to/sbom.json")
    """

    def parse(self, file_path: str) -> ParsedSBOM:
        path = Path(file_path)

        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise SBOMParseError(f"Cannot read file '{file_path}': {exc}") from exc

        # Try JSON first; fall back to XML for CycloneDX
        if self._looks_like_xml(raw_bytes):
            return self._parse_cyclonedx_xml(raw_bytes, file_path)

        try:
            data = json.loads(raw_bytes)
        except json.JSONDecodeError as exc:
            raise SBOMParseError(
                f"File '{file_path}' is not valid JSON or XML: {exc}"
            ) from exc

        fmt = self._detect_json_format(data, file_path)
        if fmt == SBOMFormat.CYCLONEDX_1_6:
            return self._parse_cyclonedx_json(data, file_path)
        return self._parse_spdx_json(data, file_path)

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_xml(raw: bytes) -> bool:
        stripped = raw.lstrip()
        return stripped.startswith(b"<") or stripped.startswith(b"<?xml")

    @staticmethod
    def _detect_json_format(data: dict, file_path: str) -> SBOMFormat:
        bom_format = data.get("bomFormat", "")
        spec_version = data.get("specVersion", "")
        spdx_version = data.get("spdxVersion", "")
        context = data.get("@context", "")

        if bom_format == "CycloneDX" and spec_version == "1.6":
            return SBOMFormat.CYCLONEDX_1_6

        if spdx_version.startswith("SPDX-3") or "spdx" in str(context).lower():
            return SBOMFormat.SPDX_3_0

        raise SBOMValidationError(
            f"File '{file_path}' does not appear to be a supported SBOM format. "
            "Expected CycloneDX 1.6 (bomFormat+specVersion) or SPDX 3.0 (spdxVersion)."
        )

    # ------------------------------------------------------------------
    # CycloneDX 1.6 — JSON
    # ------------------------------------------------------------------

    def _parse_cyclonedx_json(self, data: dict, file_path: str) -> ParsedSBOM:
        metadata_raw = data.get("metadata", {})
        metadata = SBOMMetadata(
            tool=self._cdx_tool_name(metadata_raw),
            authors=[a.get("name", "") for a in metadata_raw.get("authors", [])],
            timestamp=metadata_raw.get("timestamp"),
            component=metadata_raw.get("component", {}).get("name"),
        )

        raw_components = data.get("components")
        if raw_components is None:
            raise SBOMValidationError(
                f"CycloneDX file '{file_path}' is missing the required 'components' array."
            )

        components = [self._cdx_json_component(c, file_path, i) for i, c in enumerate(raw_components)]

        return ParsedSBOM(
            format=SBOMFormat.CYCLONEDX_1_6,
            serial_number=data.get("serialNumber"),
            metadata=metadata,
            components=components,
            raw=data,
        )

    @staticmethod
    def _cdx_tool_name(metadata: dict) -> str | None:
        tools = metadata.get("tools", {})
        # CycloneDX 1.6 tools can be a list or a dict with "components"
        if isinstance(tools, list) and tools:
            return tools[0].get("name")
        if isinstance(tools, dict):
            comps = tools.get("components", [])
            if comps:
                return comps[0].get("name")
        return None

    @staticmethod
    def _cdx_json_component(raw: dict, file_path: str, index: int) -> Component:
        name = raw.get("name")
        if not name:
            raise SBOMValidationError(
                f"CycloneDX file '{file_path}': component at index {index} is missing required field 'name'."
            )
        licenses = [
            lic.get("license", {}).get("id") or lic.get("license", {}).get("name", "")
            for lic in raw.get("licenses", [])
        ]
        return Component(
            name=name,
            version=raw.get("version"),
            purl=raw.get("purl"),
            cpe=raw.get("cpe"),
            licenses=[l for l in licenses if l],
            supplier=raw.get("supplier", {}).get("name") if isinstance(raw.get("supplier"), dict) else None,
            extra={k: v for k, v in raw.items() if k not in {"name", "version", "purl", "cpe", "licenses", "supplier"}},
        )

    # ------------------------------------------------------------------
    # CycloneDX 1.6 — XML
    # ------------------------------------------------------------------

    def _parse_cyclonedx_xml(self, raw: bytes, file_path: str) -> ParsedSBOM:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise SBOMParseError(f"File '{file_path}' contains malformed XML: {exc}") from exc

        ns = {"cdx": _CYCLONEDX_XML_NS}
        if _CYCLONEDX_XML_NS not in root.tag:
            raise SBOMValidationError(
                f"XML file '{file_path}' does not use the CycloneDX 1.6 namespace. "
                f"Found root tag: {root.tag}"
            )

        metadata = SBOMMetadata(
            timestamp=self._xml_text(root, "cdx:metadata/cdx:timestamp", ns),
            component=self._xml_text(root, "cdx:metadata/cdx:component/cdx:name", ns),
        )

        components_el = root.find("cdx:components", ns)
        if components_el is None:
            raise SBOMValidationError(
                f"CycloneDX XML file '{file_path}' is missing the required <components> element."
            )

        components = [
            self._cdx_xml_component(el, ns, file_path, i)
            for i, el in enumerate(components_el.findall("cdx:component", ns))
        ]

        return ParsedSBOM(
            format=SBOMFormat.CYCLONEDX_1_6,
            serial_number=root.get("serialNumber"),
            metadata=metadata,
            components=components,
            raw={},
        )

    @staticmethod
    def _xml_text(root: ET.Element, path: str, ns: dict) -> str | None:
        el = root.find(path, ns)
        return el.text.strip() if el is not None and el.text else None

    def _cdx_xml_component(self, el: ET.Element, ns: dict, file_path: str, index: int) -> Component:
        name = self._xml_text(el, "cdx:name", ns)
        if not name:
            raise SBOMValidationError(
                f"CycloneDX XML file '{file_path}': component at index {index} is missing required element <name>."
            )
        licenses = [
            lic_id.text.strip()
            for lic_id in el.findall("cdx:licenses/cdx:license/cdx:id", ns)
            if lic_id.text
        ]
        return Component(
            name=name,
            version=self._xml_text(el, "cdx:version", ns),
            purl=self._xml_text(el, "cdx:purl", ns),
            cpe=self._xml_text(el, "cdx:cpe", ns),
            licenses=licenses,
        )

    # ------------------------------------------------------------------
    # SPDX 3.0 — JSON-LD
    # ------------------------------------------------------------------

    def _parse_spdx_json(self, data: dict, file_path: str) -> ParsedSBOM:
        # SPDX 3.0 JSON-LD uses a graph of elements; packages live in @graph
        graph = data.get("@graph") or data.get("graph") or data.get("packages") or []

        if not isinstance(graph, list):
            raise SBOMValidationError(
                f"SPDX 3.0 file '{file_path}': expected a list under '@graph' but got {type(graph).__name__}."
            )

        creation_info = data.get("creationInfo", {})
        metadata = SBOMMetadata(
            tool=next(
                (t for t in creation_info.get("createdBy", []) if isinstance(t, str)),
                None,
            ),
            timestamp=creation_info.get("created"),
        )

        components = []
        for i, element in enumerate(graph):
            element_type = element.get("type") or element.get("@type", "")
            # Collect packages and files; skip relationships and other element types
            if not any(t in str(element_type) for t in ("Package", "File", "Snippet")):
                continue
            name = element.get("name") or element.get("spdxId")
            if not name:
                raise SBOMValidationError(
                    f"SPDX 3.0 file '{file_path}': element at index {i} is missing 'name' and 'spdxId'."
                )
            license_expr = element.get("concludedLicense") or element.get("declaredLicense")
            components.append(
                Component(
                    name=name,
                    version=element.get("versionInfo") or element.get("version"),
                    purl=self._spdx_purl(element),
                    licenses=[license_expr] if license_expr else [],
                    supplier=self._spdx_supplier(element),
                    extra={k: v for k, v in element.items() if k not in {"name", "spdxId", "versionInfo", "version", "concludedLicense", "declaredLicense"}},
                )
            )

        return ParsedSBOM(
            format=SBOMFormat.SPDX_3_0,
            serial_number=data.get("spdxId"),
            metadata=metadata,
            components=components,
            raw=data,
        )

    @staticmethod
    def _spdx_purl(element: dict) -> str | None:
        for ref in element.get("externalIdentifiers", []) or element.get("externalRefs", []):
            if "purl" in str(ref.get("externalIdentifierType", "")).lower():
                return ref.get("identifier") or ref.get("locator")
        return None

    @staticmethod
    def _spdx_supplier(element: dict) -> str | None:
        supplier = element.get("suppliedBy") or element.get("supplier")
        if isinstance(supplier, str):
            return supplier
        if isinstance(supplier, dict):
            return supplier.get("name")
        return None
