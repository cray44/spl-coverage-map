import sys
from pathlib import Path

import click

from .parser import parse_rules_directory
from .navigator import build_layer, render_summary, write_layer


@click.group()
def cli():
    pass


@cli.command()
@click.argument("rules_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None,
              help="Write Navigator JSON layer to this path")
@click.option("--name", "-n", default="Detection Coverage",
              help="Layer name shown in ATT&CK Navigator")
@click.option("--summary", is_flag=True, default=False,
              help="Print a coverage summary to stdout")
def generate(rules_dir: Path, output: Path, name: str, summary: bool):
    """Generate an ATT&CK Navigator layer from a directory of Sigma rules."""
    rules = parse_rules_directory(rules_dir)

    if not rules:
        click.echo("No rules with ATT&CK technique tags found.", err=True)
        sys.exit(1)

    if summary:
        click.echo(render_summary(rules))

    layer = build_layer(rules, layer_name=name)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        write_layer(layer, output)
        click.echo(f"Layer written to {output}  ({len(layer['techniques'])} techniques covered)")
    elif not summary:
        import json
        click.echo(json.dumps(layer, indent=2))


if __name__ == "__main__":
    cli()
