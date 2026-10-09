# -*- encoding: utf-8 -*-
"""
kfregistrar.app.cli.kfregistrar module

CLI entry point for the registrar operational network.
"""

import multicommand
from hio.base import doing
from keri import help

from kfregistrar.app.cli import commands


logger = help.ogler.getLogger()


def main():
    """Entry point for the kf-registrar CLI."""
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        return

    try:
        doers = args.handler(args)
        if not doers:
            return
        tock = 0.00125
        doist = doing.Doist(limit=0.0, tock=tock, real=True)
        doist.do(doers=doers)
    except Exception as ex:
        print(f"ERR: {ex}")
        return -1


if __name__ == "__main__":
    main()
