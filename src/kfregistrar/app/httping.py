# -*- encoding: utf-8 -*-
"""
kfregistrar.app.httping module

Falcon resources for the registrar internal controller API and external
observer-only bulk TEL API.
"""

import json

import falcon
from keri import Vrsn_2_0
from keri.app.httping import CESR_ATTACHMENT_HEADER, CESR_CONTENT_TYPE
from keri.core import Number, Parser, SerderACDC, SerderKERI
from keri.kering import (
    ConfigurationError,
    MissingAuthAttachmentError,
    MissingSenderKeyStateError,
    ValidationError,
)

from kfregistrar.core.ingesting import allRegistrySaids, knownRegistry

BULK_ROUTES = ("tels/bulk", "regs")
WALLET_ROUTES = ("tels", "tsn", "logs", "ksn", "mbx")


def _snFromQuery(qry):
    """Parse an optional sequence number from a query block."""
    sn = qry.get("sn", 0)
    if sn is None or sn == "":
        return 0
    if isinstance(sn, int):
        return sn
    return Number(num=sn).sn


def _registrySaids(qry, store, rgy):
    """Resolve registry SAIDs from a bulk query block.

    Empty ``i`` means all locally managed and hosted registries.
    """
    raw = qry.get("i")
    if raw is None or raw == "":
        return allRegistrySaids(store, rgy)
    if isinstance(raw, str):
        return [raw]
    return list(raw)


def cloneRegs(store, regks, sn=0):
    """Concatenate accepted TEL CESR for one or more registry SAIDs."""
    stream = bytearray()
    for regk in regks:
        stream.extend(store.cloneTel(regk, sn=sn))
    return bytes(stream)


def _loadQueryStream(req):
    """Read a signed qry as CESR-over-HTTP JSON+attachment or a raw CESR stream."""
    ctype = (req.content_type or "").split(";")[0].strip().lower()
    if ctype and ctype != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(
            falcon.HTTP_NOT_ACCEPTABLE,
            title="Content type error",
            description="Unacceptable content type.",
        )
    raw = req.bounded_stream.read()
    if not raw:
        raise falcon.HTTPBadRequest(description="empty body")
    atc = req.get_header(CESR_ATTACHMENT_HEADER, default=None)
    if atc and raw.lstrip()[:1] == b"{":
        payload = json.loads(raw)
        serder = SerderKERI(sad=payload)
        ims = bytearray(serder.raw)
        ims.extend(atc.encode("utf-8") if isinstance(atc, str) else atc)
        return ims
    ims = bytearray(raw)
    if atc and raw.lstrip()[:1] != b"{":
        ims.extend(atc.encode("utf-8") if isinstance(atc, str) else atc)
    return ims


def _parseAcdc(acdcSad):
    """Build a SerderACDC from a SAD dict or raw CESR bytes/text."""
    if isinstance(acdcSad, dict):
        return SerderACDC(sad=acdcSad)
    raw = acdcSad.encode("utf-8") if isinstance(acdcSad, str) else acdcSad
    return SerderACDC(raw=raw)


class HealthEnd:
    """Liveness probe. No TEL material."""

    def on_get(self, _req, rep):
        rep.media = dict(status="ok")
        rep.status = falcon.HTTP_200


class QueryRejectEnd:
    """Wallet-shaped GET /query is never served on the registrar external API."""

    def on_get(self, _req, _rep):
        raise falcon.HTTPForbidden(
            description="registrar external API does not serve wallet queries"
        )

    def on_post(self, _req, _rep):
        raise falcon.HTTPForbidden(
            description="registrar external API does not serve wallet queries"
        )


class RegistriesCollectionEnd:
    """Internal create/list of registries this node governs or hosts."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_get(self, _req, rep):
        items = []
        seen = set()
        for name, registry in self.ctx.rgy.names.items():
            items.append(dict(
                name=name,
                regk=registry.regk,
                issuer=registry.hab.pre,
            ))
            seen.add(registry.regk)
        for regk in allRegistrySaids(self.ctx.rgy.store, self.ctx.rgy):
            if regk in seen:
                continue
            rip = self.ctx.rgy.store.seqEvent(regk, 0)
            issuer = rip.sad.get("i") if rip is not None else None
            items.append(dict(name=None, regk=regk, issuer=issuer))
        rep.media = dict(registries=items)
        rep.status = falcon.HTTP_200

    def on_post(self, req, rep):
        body = req.media or {}
        name = body.get("name")
        if not name:
            raise falcon.HTTPBadRequest(description="'name' is required")
        prefix = body.get("prefix") or self.ctx.hab.pre
        kwa = {}
        if body.get("uuid"):
            kwa["uuid"] = body["uuid"]
        try:
            registry = self.ctx.registrar.makeRegistry(name=name, prefix=prefix, **kwa)
        except ConfigurationError as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex

        rip = self.ctx.rgy.store.event(registry.regk)
        seal = dict(i=registry.regk, s=rip.sad["n"], d=rip.said)
        self.ctx.hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
        registry.anchorMsg(rip.said)

        rep.media = dict(
            name=name,
            regk=registry.regk,
            issuer=prefix,
            said=rip.said,
        )
        rep.status = falcon.HTTP_201


class RegistryResourceEnd:
    """Internal read of one registry TEL by SAID."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_get(self, req, rep, regk):
        if not knownRegistry(self.ctx.rgy.store, self.ctx.rgy, regk):
            raise falcon.HTTPNotFound(description=f"unknown registry {regk}")
        sn = req.get_param_as_int("sn") or 0
        data = self.ctx.rgy.store.cloneTel(regk, sn=sn)
        rep.set_header("Content-Type", CESR_CONTENT_TYPE)
        rep.status = falcon.HTTP_200
        rep.data = data


class IngestEnd:
    """Internal controller publish of pre-built TEL events plus issuer KEL."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_post(self, req, rep):
        body = req.media or {}
        kel = body.get("kel")
        tel = body.get("tel")
        if not tel:
            raise falcon.HTTPBadRequest(description="'tel' is required")
        if kel is None:
            kel = ""

        rep.media = self.ctx.ingester.ingest(kel=kel, tel=tel)
        rep.status = falcon.HTTP_200


class RegistryUpdateEnd:
    """Internal append of a blindable update, then KEL-anchor it locally."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_post(self, req, rep, regk):
        if regk not in self.ctx.rgy.regs:
            raise falcon.HTTPNotFound(description=f"unknown registry {regk}")
        body = req.media or {}
        acdcSad = body.get("acdc")
        state = body.get("state", "issued")
        if not acdcSad:
            raise falcon.HTTPBadRequest(description="'acdc' is required")

        try:
            acdc = _parseAcdc(acdcSad)
            blinder, bup = self.ctx.registrar.issue(regk, acdc=acdc, state=state)
        except (ConfigurationError, ValidationError) as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex

        seal = dict(i=regk, s=bup.sad["n"], d=bup.said)
        self.ctx.hab.interact(data=[seal], framed=True, gvrsn=Vrsn_2_0)
        self.ctx.rgy.regs[regk].anchorMsg(bup.said)

        rep.media = dict(
            said=bup.said,
            sn=bup.sad["n"],
            blid=blinder.said,
            state=state,
        )
        rep.status = falcon.HTTP_201


class BulkQueryEnd:
    """External signed V2 qry POST. Observer allow-list plus KRAM, then bulk CESR."""

    def __init__(self, ctx):
        self.ctx = ctx

    def on_get(self, _req, _rep):
        raise falcon.HTTPForbidden(
            description="registrar external API does not serve wallet queries"
        )

    def on_post(self, req, rep):
        try:
            ims = _loadQueryStream(req)
        except falcon.HTTPError:
            raise
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex

        try:
            dom = Parser(version=Vrsn_2_0).parseOne(
                ims=bytearray(ims), framed=True, processive=False
            )
        except Exception as ex:
            raise falcon.HTTPBadRequest(description=str(ex)) from ex
        if not getattr(dom, "serder", None):
            raise falcon.HTTPBadRequest(description="unable to parse signed query")
        serder = dom.serder
        if serder.ilk != "qry":
            raise falcon.HTTPBadRequest(description="external API accepts qry messages only")

        route = serder.ked.get("r", "")
        qry = serder.ked.get("q") or {}
        if not isinstance(qry, dict):
            qry = {}

        if route in WALLET_ROUTES or "vcid" in qry:
            raise falcon.HTTPForbidden(
                description="wallet-shaped TEL queries are not served by the registrar"
            )
        if route not in BULK_ROUTES:
            raise falcon.HTTPForbidden(
                description=f"invalid bulk query route {route}"
            )

        sender = serder.pre
        if not self.ctx.observers or sender not in self.ctx.observers:
            raise falcon.HTTPForbidden(description="observer AID is not allow-listed")

        kwa = dict(
            sigers=list(dom.sigers),
            cigars=list(dom.cigars),
            lsgs=list(dom.lsgs),
            tsgs=list(dom.tsgs),
            sscs=list(dom.sscs),
            ssts=list(dom.ssts),
        )

        kramer = self.ctx.kvy.kramer
        if kramer is not None:
            kramer.reconcileConfig()
            try:
                result = kramer.intake(serder, kwa)
            except (MissingAuthAttachmentError, MissingSenderKeyStateError) as ex:
                raise falcon.HTTPUnauthorized(description=str(ex)) from ex
            if result is None:
                raise falcon.HTTPUnauthorized(description="KRAM rejected query")

        sn = _snFromQuery(qry)
        store = self.ctx.rgy.store
        regks = _registrySaids(qry, store, self.ctx.rgy)
        unknown = [
            regk for regk in regks
            if not knownRegistry(store, self.ctx.rgy, regk)
        ]
        if unknown and qry.get("i"):
            raise falcon.HTTPNotFound(
                description=f"unknown registry {unknown[0]}"
            )

        data = cloneRegs(
            store,
            [regk for regk in regks if knownRegistry(store, self.ctx.rgy, regk)],
            sn=sn,
        )
        rep.set_header("Content-Type", CESR_CONTENT_TYPE)
        rep.status = falcon.HTTP_200
        rep.data = data
