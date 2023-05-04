# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.

from typing import Optional

from rich.console import Console
from rich.table import Table


def print_info(message: str):
    console = Console()
    console.print(message)


def print_item(message: str, tabs: Optional[int] = 0):
    console = Console()
    console.print(f"  [cyan]-[/cyan] {message}")


def print_warning(message: str):
    console = Console()
    console.print(f"[bold yellow]WARNING: {message}[/bold yellow]")


def print_error(message: str):
    console = Console()
    console.print(f"[bold red]ERROR: {message}[/bold red]")


def print_success(message: str):
    console = Console()
    console.print(f"[bold green]{message}[/bold green]")


def table(columns: list, rows: list):
    console = Console()
    table = Table(show_header=True, header_style="bold")

    for column in columns:
        table.add_column(column)

    for row in rows:
        table.add_row(*row)

    console.print(table)


def print_output(output: str, filename: Optional[str] = None):
    if not output:
        return

    if filename:
        with open(filename.strip(), "a") as out:
            for entry in output:
                if entry["type"] == "info":
                    out.write("[*] {0}\n".format(entry["data"]))
                elif entry["type"] == "item":
                    out.write("  [-] {0}\n".format(entry["data"]))
                elif entry["type"] == "warning":
                    out.write("[!] {0}\n".format(entry["data"]))
                elif entry["type"] == "error":
                    out.write("[!] {0}\n".format(entry["data"]))
                elif entry["type"] == "success":
                    out.write("[+] {0}\n".format(entry["data"]))
                elif entry["type"] == "table":
                    out.write(
                        str(
                            table(
                                columns=entry["data"]["columns"],
                                rows=entry["data"]["rows"],
                            )
                        )
                    )
                    out.write("\n")
                else:
                    out.write("{0}\n".format(entry["data"]))
        print_success("Output written to {0}".format(filename))
    else:
        for entry in output:
            if entry["type"] == "info":
                print_info(entry["data"])
            elif entry["type"] == "item":
                print_item(entry["data"])
            elif entry["type"] == "warning":
                print_warning(entry["data"])
            elif entry["type"] == "error":
                print_error(entry["data"])
            elif entry["type"] == "success":
                print_success(entry["data"])
            elif entry["type"] == "table":
                table(columns=entry["data"]["columns"], rows=entry["data"]["rows"])
            else:
                print(entry["data"])
