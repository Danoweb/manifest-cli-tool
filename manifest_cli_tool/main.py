import click

from manifest_cli_tool.opensearch_client import (
    OpenSearchClientError,
    index_processed,
    query_components,
    upload_original,
)
from manifest_cli_tool.sbom_parser import SBOMError, SBOMParser


@click.group()
def cli():
    pass


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("sbom_file", type=click.Path(exists=True, readable=True, dir_okay=False))
def ingest(sbom_file: str):
    """Ingest an SBOM file into OpenSearch."""
    parser = SBOMParser()

    try:
        sbom = parser.parse(sbom_file)
    except SBOMError as exc:
        raise click.ClickException(str(exc))

    click.echo(f"Format   : {sbom.format.value}")
    click.echo(f"Serial   : {sbom.serial_number or 'n/a'}")
    click.echo(f"Subject  : {sbom.metadata.component or 'n/a'}")
    click.echo(f"Timestamp: {sbom.metadata.timestamp or 'n/a'}")
    click.echo(f"Components: {len(sbom.components)}")

    try:
        orig_id = upload_original(sbom_file)
        click.echo(f"Stored original  -> 'originals/{orig_id}'")

        proc_id = index_processed(sbom, sbom_file)
        click.echo(f"Stored processed -> 'processed/{proc_id}'")
    except OpenSearchClientError as exc:
        raise click.ClickException(str(exc))


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--component", "component", default=None, metavar="NAME",
              help="Match SBOMs that contain this component name.")
@click.option("--version", "version", default=None, metavar="VERSION",
              help="Restrict --component match to this version.")
@click.option("--license", "license_", default=None, metavar="LICENSE",
              help="Match SBOMs that contain a component with this license.")
def query(component: str | None, version: str | None, license_: str | None):
    """Query the processed SBOM index.

    \b
    Examples:
      sbom-cli query --component requests
      sbom-cli query --component requests --version 2.31.0
      sbom-cli query --license MIT
      sbom-cli query --component requests --license Apache-2.0
      sbom-cli query --component requests --version 2.31.0 --license Apache-2.0
    """
    if not component and not license_:
        raise click.UsageError("Provide at least one of --component or --license.")
    if version and not component:
        raise click.UsageError("--version requires --component.")

    try:
        results = query_components(name=component, version=version, license=license_)
    except OpenSearchClientError as exc:
        raise click.ClickException(str(exc))

    if not results:
        click.echo("No matching documents found.")
        return

    click.echo(f"Found {len(results)} document(s):\n")
    for doc in results:
        click.echo(f"  File   : {doc['filename']}")
        click.echo(f"  Format : {doc['format']}")
        if doc["serial_number"]:
            click.echo(f"  Serial : {doc['serial_number']}")
        click.echo(f"  Matched components ({len(doc['matched_components'])}):")
        for comp in doc["matched_components"]:
            parts = [f"    - {comp['name']}"]
            if comp.get("version"):
                parts.append(f"v{comp['version']}")
            if comp.get("purl"):
                parts.append(f"({comp['purl']})")
            if comp.get("licenses"):
                parts.append(f"[{', '.join(comp['licenses'])}]")
            click.echo(" ".join(parts))
        click.echo()


if __name__ == "__main__":
    cli()
