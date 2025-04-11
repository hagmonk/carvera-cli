"""
Carvera CLI - A command-line tool for managing Carvera CNC machines
"""

__version__ = "0.1.0"

from carvera_cli.main import main

# This function is a direct entry point for CLI use
def cli_main():
    """
    Entry point for the CLI command.
    This function is referenced in pyproject.toml
    """
    import sys
    sys.exit(main()) 