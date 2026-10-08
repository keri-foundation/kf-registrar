# -*- encoding: utf-8 -*-
"""
kfregistrar.core.serving module

Dual HTTP registrar node: localhost controller API and observer-only bulk TEL API.
"""

from urllib.parse import urlsplit

import falcon
from hio.base import doing
from hio.core import http
from keri import help
from keri.acdc import Registrar, Regery
from keri.app.indirecting import createHttpServer
from keri.core import Kevery
from keri.core.kraming import Kramer
from keri.db.basing import BaserDoer

from kfregistrar.app import httping
from kfregistrar.core.ingesting import ControllerIngester


logger = help.ogler.getLogger()

CORS_EXPOSE = [
    "cesr-attachment",
    "cesr-date",
    "content-type",
    "signature",
    "signature-input",
    "signify-resource",
    "signify-timestamp",
]

DEFAULT_KRAM_CONFIG = {
    "kram": {
        "enabled": True,
        "denials": [],
        "caches": {
            "~": [1000, 5000, 60000, 300000, 5000, 60000, 300000],
        },
    }
}


class StaticConfig:
    """Minimal Configer duck-type for KRAM settings."""

    def __init__(self, data):
        self.data = data

    def get(self):
        return self.data


class Context(doing.DoDoer):
    """Running registrar node: Habery, Regery, KRAM, and both Falcon apps."""

    def __init__(self, hby, hab, rgy, kvy, observers=None):
        self.hby = hby
        self.hab = hab
        self.rgy = rgy
        self.registrar = Registrar(rgy=rgy)
        self.kvy = kvy
        self.ingester = ControllerIngester(hby=hby, store=rgy.store, kvy=kvy)
        self.observers = osetOf(observers)
        self.internalApp = None
        self.externalApp = None
        super(Context, self).__init__(doers=[doing.doify(self.escrowDo)])

    def escrowDo(self, tymth=None, tock=0.0, **kwa):
        """Replay registry escrows and retry pending controller ingest."""
        self.wind(tymth)
        self.tock = tock
        _ = yield self.tock
        while True:
            self.rgy.processEscrows()
            self.ingester.retryPending()
            yield self.tock


def osetOf(values):
    """Return a set of observer AIDs from a sequence or None."""
    if not values:
        return set()
    return set(values)


def _configWithKram(cf):
    """Ensure a KRAM block exists so Kramer.intake actually authenticates."""
    data = {}
    if cf is not None:
        loaded = cf.get()
        if loaded:
            data = dict(loaded)
    if "kram" not in data:
        data = {**DEFAULT_KRAM_CONFIG, **data}
        data["kram"] = dict(DEFAULT_KRAM_CONFIG["kram"])
    return StaticConfig(data)


def _observersFromConfig(cf):
    """Read observer AIDs from the kf-registrar config block."""
    if cf is None:
        return []
    data = cf.get() or {}
    block = data.get("kf-registrar") or data.get("kfregistrar") or {}
    return list(block.get("observers") or data.get("observers") or [])


def _applyCurls(cf, host, port):
    """Override advertised host/port from kf-registrar.curls when present."""
    if cf is None:
        return host, port
    data = cf.get() or {}
    block = data.get("kf-registrar") or {}
    curls = block.get("curls") or []
    if not curls:
        return host, port
    splits = urlsplit(curls[0])
    if splits.hostname:
        host = splits.hostname
    if splits.port:
        port = splits.port
    return host, port


def _corsApp():
    return falcon.App(
        middleware=falcon.CORSMiddleware(
            allow_origins="*",
            allow_credentials="*",
            expose_headers=CORS_EXPOSE,
        )
    )


def loadInternalEnds(app, ctx):
    """Register controller (issuer) routes on the internal Falcon app."""
    app.add_route("/health", httping.HealthEnd())
    app.add_route("/registries", httping.RegistriesCollectionEnd(ctx))
    app.add_route("/registries/{regk}", httping.RegistryResourceEnd(ctx))
    app.add_route("/registries/{regk}/updates", httping.RegistryUpdateEnd(ctx))
    app.add_route("/ingest", httping.IngestEnd(ctx))


def loadExternalEnds(app, ctx):
    """Register observer-only routes on the external Falcon app."""
    app.add_route("/health", httping.HealthEnd())
    app.add_route("/", httping.BulkQueryEnd(ctx))
    app.add_route("/query", httping.QueryRejectEnd())


def makeContext(hby, alias="registrar", observers=None, **kwa):
    """Build the registrar Context and Falcon apps without binding sockets.

    Parameters:
        hby (Habery): habitat environment that owns the issuer identifier.
        alias (str): habitat name for the registrar/issuer controller.
        observers (list[str] | None): observer AIDs allowed on the external API.
            Combined with any ``observers`` list in Habery config.

    Returns:
        Context: registrar node with internalApp and externalApp attached.
    """
    hab = hby.habByName(name=alias)
    if hab is None:
        hab = hby.makeHab(name=alias, transferable=True, **kwa)

    rgy = Regery(hby=hby, name=hby.name, base=hby.base, temp=hby.temp)

    cf = _configWithKram(hby.cf)
    kvy = Kevery(
        db=hby.db,
        cf=cf,
        enableKram=True,
        lax=True,
        local=False,
    )
    if kvy.kramer is None:
        kvy.kramer = Kramer(db=hby.db, cf=cf, cues=kvy.cues)

    obs = osetOf(observers) | osetOf(_observersFromConfig(hby.cf))
    for aid in obs:
        kvy.allowList.add(aid)

    ctx = Context(hby=hby, hab=hab, rgy=rgy, kvy=kvy, observers=obs)

    internalApp = _corsApp()
    loadInternalEnds(internalApp, ctx)
    ctx.internalApp = internalApp

    externalApp = _corsApp()
    loadExternalEnds(externalApp, ctx)
    ctx.externalApp = externalApp
    return ctx


def setup(
    hby,
    alias="registrar",
    bootHost="127.0.0.1",
    bootPort=6631,
    host="127.0.0.1",
    port=6632,
    observers=None,
    keypath=None,
    certpath=None,
    cafilepath=None,
    **kwa,
):
    """Initialize dual HTTP servers for one registrar node.

    Internal (bootHost:bootPort) is the controller API. External (host:port)
    is bulk TEL CESR for KRAM-whitelisted observers only.

    Parameters:
        hby (Habery): habitat environment that owns the issuer identifier.
        alias (str): habitat name for the registrar/issuer controller.
        bootHost (str): bind address for the internal controller API.
        bootPort (int): port for the internal controller API.
        host (str): bind address for the observer-facing API.
        port (int): port for the observer-facing API.
        observers (list[str] | None): observer AIDs allowed on the external API.
            Combined with any ``observers`` list in Habery config.
        keypath, certpath, cafilepath: optional TLS material for both servers.

    Returns:
        list: HIO doers including the registrar Context and both HTTP servers.
    """
    ctx = makeContext(hby=hby, alias=alias, observers=observers, **kwa)

    advertisedHost, advertisedPort = _applyCurls(hby.cf, host, port)
    ctx.host = advertisedHost
    ctx.port = advertisedPort

    bootServer = createHttpServer(
        host=bootHost,
        port=bootPort,
        app=ctx.internalApp,
        keypath=keypath,
        certpath=certpath,
        cafilepath=cafilepath,
    )
    if not bootServer.reopen():
        raise RuntimeError(f"cannot create internal HTTP server on port {bootPort}")
    bootSrvrDoer = http.ServerDoer(server=bootServer)

    server = createHttpServer(
        host=host,
        port=port,
        app=ctx.externalApp,
        keypath=keypath,
        certpath=certpath,
        cafilepath=cafilepath,
    )
    if not server.reopen():
        raise RuntimeError(f"cannot create external HTTP server on port {port}")
    srvrDoer = http.ServerDoer(server=server)

    regDoer = BaserDoer(baser=ctx.rgy.baser)
    logger.info(
        "Registrar %s : %s internal http/%s:%s external http/%s:%s",
        ctx.hab.name,
        ctx.hab.pre,
        bootHost,
        bootPort,
        host,
        port,
    )
    return [ctx, regDoer, bootSrvrDoer, srvrDoer]
