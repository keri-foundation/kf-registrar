# -*- encoding: utf-8 -*-
"""
kfregistrar.app.cli.commands.start module

``kf-registrar start``: Habery plus dual HTTP registrar node.
"""

import argparse
import logging
import sys

from hio.base import doing
from keri import __version__, help
from keri.app import Configer, Habery, HaberyDoer, Keeper
from keri.cli.common.existing import setupHby
from keri.kering import AuthError, Vrsn_2_0

from kfregistrar.core import serving


d = "Runs KERI Foundation registrar controller.\n"
d += "Example:\nkf-registrar start -a registrar -H 6632 -bp 6631\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument(
    "-V",
    "--version",
    action="version",
    version=__version__,
    help="Prints out version of script runner.",
)
parser.add_argument(
    "-H",
    "--http",
    action="store",
    default=6632,
    help="Local port number the external HTTP server listens on. Default is 6632.",
)
parser.add_argument(
    "-o",
    "--host",
    action="store",
    default="127.0.0.1",
    help="Local host IP address the external HTTP server listens on. Default is 127.0.0.1.",
)
parser.add_argument(
    "--bootport",
    "-bp",
    action="store",
    default=6631,
    help="Local port number the internal HTTP server listens on. Default is 6631.",
)
parser.add_argument(
    "--boothost",
    "-bh",
    action="store",
    default="127.0.0.1",
    help="Local host IP address the internal HTTP server listens on. Default is 127.0.0.1.",
)
parser.add_argument(
    "-n",
    "--name",
    action="store",
    default="registrar",
    help="Name of controller. Default is registrar.",
)
parser.add_argument(
    "--alias",
    "-a",
    help="human readable alias for the registrar identifier prefix",
    default="registrar",
)
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="22 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=None,
)
parser.add_argument(
    "--config-dir",
    "-c",
    dest="configDir",
    help="directory override for configuration data",
)
parser.add_argument(
    "--config-file",
    dest="configFile",
    action="store",
    default=None,
    help="configuration filename override",
)
parser.add_argument(
    "--observer",
    action="append",
    dest="observers",
    default=None,
    help="Observer AID allowed to pull bulk TEL. Repeatable.",
)
parser.add_argument(
    "--loglevel",
    action="store",
    required=False,
    default="INFO",
    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is INFO",
)
parser.add_argument("--keypath", action="store", required=False, default=None)
parser.add_argument("--certpath", action="store", required=False, default=None)
parser.add_argument("--cafilepath", action="store", required=False, default=None)
parser.add_argument(
    "--no-prompt",
    action="store_true",
    default=None,
    required=False,
    help="Disable interactive prompt",
    dest="noPrompt",
)

FORMAT = "%(asctime)s [kf-registrar] %(levelname)-8s %(message)s"


def launch(args):
    """Configure logging and start the registrar operational node."""
    help.ogler.level = logging.getLevelName(args.loglevel)
    baseFormatter = logging.Formatter(FORMAT)
    baseFormatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(baseFormatter)
    logger = help.ogler.getLogger()

    logger.info(
        "******* Starting kf-registrar internally: http/%s:%s, externally: http/%s:%s ******",
        args.boothost,
        args.bootport,
        args.host,
        args.http,
    )

    runRegistrar(args)

    logger.info(
        "******* Ended kf-registrar internally: http/%s:%s, externally: http/%s:%s ******",
        args.boothost,
        args.bootport,
        args.host,
        args.http,
    )


def runRegistrar(args, expire=0.0):
    """Set up Habery and run the registrar until expiry."""
    noPrompt = args.noPrompt if args.noPrompt is not None else not sys.stdin.isatty()

    ks = Keeper(name=args.name, base=args.base, temp=False, reopen=True)
    aeid = ks.gbls.get("aeid")
    ks.close()

    cf = None
    if args.configFile:
        cf = Configer(
            name=args.configFile,
            headDirPath=args.configDir,
            temp=False,
            reopen=True,
            clear=False,
        )

    hby = None
    try:
        if aeid is None:
            hby = Habery(name=args.name, base=args.base, bran=args.bran, cf=cf, version=Vrsn_2_0)
        else:
            if not args.bran and noPrompt:
                raise AuthError(
                    f"passcode required for keystore {args.name!r} but prompting is disabled."
                )
            hby = setupHby(
                name=args.name,
                base=args.base,
                bran=args.bran,
                cf=cf,
                noPrompt=noPrompt,
                version=Vrsn_2_0,
            )

        hbyDoer = HaberyDoer(habery=hby)
        doers = [hbyDoer]
        doers.extend(
            serving.setup(
                hby=hby,
                alias=args.alias,
                bootHost=args.boothost,
                bootPort=int(args.bootport),
                host=args.host,
                port=int(args.http),
                observers=args.observers,
                keypath=args.keypath,
                certpath=args.certpath,
                cafilepath=args.cafilepath,
            )
        )

        tock = 0.00125
        doist = doing.Doist(limit=expire, tock=tock, real=True)
        doist.do(doers=doers)
    finally:
        if hby is not None:
            hby.close()
