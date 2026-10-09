# -*- encoding: utf-8 -*-
import falcon
from falcon import testing

from keri import Vrsn_2_0
from keri.acdc import Regery, acdcmap, blindate, regcept
from keri.acdc.regbasing import RegBaser
from keri.app.habbing import openHab, openHby
from keri.app.configing import Configer
from keri.app.httping import CESR_CONTENT_TYPE
from keri.core import Blinder, Kevery, SerderACDC, query
from keri.core.signing import Salter
from keri.help import helping

from kfregistrar.core.serving import Context, makeContext
from kfregistrar.core.ingesting import ControllerIngester, ingestKel


STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
SALT = Salter(raw=b"0123456789abcdef").qb64


def _postCesr(client, hab, serder, path="/"):
    """POST a signed CESR query as an observer (or impostor) would."""
    msg = hab.endorse(serder, last=True, framed=False, gvrsn=Vrsn_2_0)
    headers = {"Content-Type": CESR_CONTENT_TYPE}
    return client.simulate_post(path, body=bytes(msg), headers=headers)


def _telIlks(raw):
    """Read concatenated ACDC TEL bodies into ilk labels."""
    ims = bytearray(raw)
    ilks = []
    while ims:
        serder = SerderACDC(raw=ims)
        ilks.append(serder.ilk)
        del ims[:serder.size]
    return ilks


def _bulkQuery(hab, regk=None, route="tels/bulk", **qextra):
    q = dict(qextra)
    if regk is not None:
        q["i"] = regk
    return query(
        pre=hab.pre,
        route=route,
        query=q,
        stamp=helping.nowIso8601(),
        version=Vrsn_2_0,
    )


def _seal(serder):
    return dict(s=serder.sad["n"], d=serder.said)


def _anchor(hab, *serders):
    hab.interact(data=[_seal(serder) for serder in serders])


def _telStream(*serders):
    stream = bytearray()
    for serder in serders:
        stream.extend(serder.raw)
    return bytes(stream)


def _kelClone(hab):
    """Return CESR text of the habitat's KEL for controller ingest."""
    stream = bytearray()
    for msg in hab.db.clonePreIter(pre=hab.pre, gvrsn=Vrsn_2_0):
        stream.extend(msg)
    return stream.decode("utf-8")


def test_internal_rip_bup_land_in_regbaser():
    """Controller can create a registry and append bup via the internal API."""
    with openHby(name="kf-reg-internal", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="registrar")
        ctx = makeContext(hby=hby, alias="registrar", observers=[])
        try:
            client = testing.TestClient(ctx.internalApp)

            created = client.simulate_post("/registries", json=dict(name="sedi"))
            assert created.status == falcon.HTTP_201
            regk = created.json["regk"]
            assert ctx.rgy.store.seqEvent(regk, 0).ilk == "rip"

            listed = client.simulate_get("/registries")
            assert listed.status == falcon.HTTP_200
            assert listed.json["registries"][0]["regk"] == regk

            acdc = acdcmap(
                israid=ctx.hab.pre,
                regid=regk,
                attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                iseaid=ctx.hab.pre,
            )
            updated = client.simulate_post(
                f"/registries/{regk}/updates",
                json=dict(acdc=acdc.sad, state="issued"),
            )
            assert updated.status == falcon.HTTP_201
            assert ctx.rgy.store.seqEvent(regk, 1).ilk == "bup"
            assert ctx.rgy.store.headEvent(regk).said == updated.json["said"]

            cloned = client.simulate_get(f"/registries/{regk}")
            assert cloned.status == falcon.HTTP_200
            assert cloned.headers["content-type"] == CESR_CONTENT_TYPE
            assert cloned.content == ctx.rgy.store.cloneTel(regk)
        finally:
            ctx.rgy.close()


def test_whitelisted_observer_pulls_contiguous_tel():
    """Allow-listed observer POST of tels/bulk returns rip then bup as CESR."""
    with openHby(name="kf-reg-obs", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="registrar")
        observer = hby.makeHab(name="observer")
        ctx = makeContext(hby=hby, alias="registrar", observers=[observer.pre])
        try:
            inner = testing.TestClient(ctx.internalApp)
            created = inner.simulate_post("/registries", json=dict(name="sedi"))
            regk = created.json["regk"]
            acdc = acdcmap(
                israid=ctx.hab.pre,
                regid=regk,
                attribute=dict(d="", LEI="254900OPPU84GM83MG36"),
                iseaid=ctx.hab.pre,
            )
            inner.simulate_post(
                f"/registries/{regk}/updates",
                json=dict(acdc=acdc.sad, state="issued"),
            )

            outer = testing.TestClient(ctx.externalApp)
            qry = _bulkQuery(observer, regk=regk, route="tels/bulk")
            response = _postCesr(outer, observer, qry)
            assert response.status == falcon.HTTP_200
            assert response.headers["content-type"] == CESR_CONTENT_TYPE
            assert response.content == ctx.rgy.store.cloneTel(regk)
            assert _telIlks(response.content) == ["rip", "bup"]
        finally:
            ctx.rgy.close()


def test_non_observer_and_wallet_shaped_queries_rejected():
    """External API rejects non-observer AIDs and wallet-shaped TEL queries."""
    with openHby(name="kf-reg-deny", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="registrar")
        observer = hby.makeHab(name="observer")
        wallet = hby.makeHab(name="wallet")
        ctx = makeContext(hby=hby, alias="registrar", observers=[observer.pre])
        try:
            inner = testing.TestClient(ctx.internalApp)
            created = inner.simulate_post("/registries", json=dict(name="sedi"))
            regk = created.json["regk"]

            outer = testing.TestClient(ctx.externalApp)

            walletQry = _bulkQuery(wallet, regk=regk, route="tels/bulk")
            denied = _postCesr(outer, wallet, walletQry)
            assert denied.status == falcon.HTTP_403

            walletShaped = _bulkQuery(observer, route="tels", vcid="EfakeCredentialSaid")
            shaped = _postCesr(outer, observer, walletShaped)
            assert shaped.status == falcon.HTTP_403

            vcidBulk = _bulkQuery(observer, regk=regk, route="tels/bulk", vcid="Efake")
            vcid = _postCesr(outer, observer, vcidBulk)
            assert vcid.status == falcon.HTTP_403

            queryGet = outer.simulate_get(f"/query?typ=tel&reg={regk}")
            assert queryGet.status == falcon.HTTP_403

            missing = outer.simulate_get("/registries")
            assert missing.status == falcon.HTTP_404
            missingPost = outer.simulate_post("/registries", json=dict(name="nope"))
            assert missingPost.status == falcon.HTTP_404
        finally:
            ctx.rgy.close()


def test_health_on_both_apis():
    """Liveness is available on both APIs and leaks no TEL."""
    with openHby(name="kf-reg-health", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="registrar")
        ctx = makeContext(hby=hby, alias="registrar", observers=[])
        try:
            for app in (ctx.internalApp, ctx.externalApp):
                client = testing.TestClient(app)
                response = client.simulate_get("/health")
                assert response.status == falcon.HTTP_200
                assert response.json["status"] == "ok"
        finally:
            ctx.rgy.close()


def test_controller_ingest_hosts_foreign_tel_for_observer_bulk():
    """Wallet-built TEL + KEL via admin ingest is served on observer bulk."""
    with openHab(name="kf-wallet", temp=True, version=Vrsn_2_0) as (_whby, wallet):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        _anchor(wallet, rip)
        acdc = acdcmap(
            israid=wallet.pre,
            regid=rip.said,
            attribute=dict(d="", name="presentation"),
        )
        blinder = Blinder.blind(
            acdc=acdc.said, state="issued", salt=SALT, sn=1
        )
        bup = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        _anchor(wallet, bup)
        kel = _kelClone(wallet)
        tel = _telStream(rip, bup).decode("utf-8")
        telBytes = _telStream(rip, bup)
        regk = rip.said
        walletPre = wallet.pre

    with openHby(name="kf-reg-ingest", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="registrar")
        observer = hby.makeHab(name="observer")
        ctx = makeContext(hby=hby, alias="registrar", observers=[observer.pre])
        try:
            inner = testing.TestClient(ctx.internalApp)
            ingested = inner.simulate_post(
                "/ingest",
                json=dict(kel=kel, tel=tel),
            )
            assert ingested.status == falcon.HTTP_200
            assert regk in ingested.json["accepted"]
            assert ingested.json["accepted"][regk] == 2
            assert ctx.rgy.store.cloneTel(regk) == telBytes

            listed = inner.simulate_get("/registries")
            assert listed.status == falcon.HTTP_200
            hosted = [item for item in listed.json["registries"] if item["regk"] == regk]
            assert len(hosted) == 1
            assert hosted[0]["name"] is None
            assert hosted[0]["issuer"] == walletPre

            cloned = inner.simulate_get(f"/registries/{regk}")
            assert cloned.status == falcon.HTTP_200
            assert cloned.content == telBytes

            outer = testing.TestClient(ctx.externalApp)
            qry = _bulkQuery(observer, regk=regk, route="tels/bulk")
            response = _postCesr(outer, observer, qry)
            assert response.status == falcon.HTTP_200
            assert response.content == telBytes
            assert _telIlks(response.content) == ["rip", "bup"]
        finally:
            ctx.rgy.close()


def test_controller_ingest_pending_until_kel_anchors():
    """Unanchored TEL stays pending and is not served until KEL is ingested."""
    with openHab(name="kf-wallet-pend", temp=True, version=Vrsn_2_0) as (_whby, wallet):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        acdc = acdcmap(
            israid=wallet.pre,
            regid=rip.said,
            attribute=dict(d="", name="presentation"),
        )
        blinder = Blinder.blind(
            acdc=acdc.said, state="issued", salt=SALT, sn=1
        )
        bup = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        tel = _telStream(rip, bup).decode("utf-8")
        telBytes = _telStream(rip, bup)
        regk = rip.said

        with openHby(name="kf-reg-pend", base="test", temp=True, version=Vrsn_2_0) as hby:
            hby.makeHab(name="registrar")
            observer = hby.makeHab(name="observer")
            ctx = makeContext(hby=hby, alias="registrar", observers=[observer.pre])
            try:
                inner = testing.TestClient(ctx.internalApp)
                pending = inner.simulate_post(
                    "/ingest",
                    json=dict(kel="", tel=tel),
                )
                assert pending.status == falcon.HTTP_200
                assert regk in pending.json["pending"]
                assert ctx.rgy.store.head(regk) is None

                outer = testing.TestClient(ctx.externalApp)
                qry = _bulkQuery(observer, regk=regk, route="tels/bulk")
                missing = _postCesr(outer, observer, qry)
                assert missing.status == falcon.HTTP_404

                _anchor(wallet, rip, bup)
                kel = _kelClone(wallet)
                accepted = inner.simulate_post(
                    "/ingest",
                    json=dict(kel=kel, tel=tel),
                )
                assert accepted.status == falcon.HTTP_200
                assert regk in accepted.json["accepted"]
                assert ctx.rgy.store.headEvent(regk).said == bup.said

                qry2 = _bulkQuery(observer, regk=regk, route="tels/bulk")
                response = _postCesr(outer, observer, qry2)
                assert response.status == falcon.HTTP_200
                assert response.content == telBytes
            finally:
                ctx.rgy.close()


def test_controller_ingest_rejects_conflicting_anchored_tel_fork():
    """A second valid seal for the same TEL slot cannot split stored history."""
    with openHab(name="kf-reg-fork", temp=True, version=Vrsn_2_0) as (_whby, wallet):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        acdc = acdcmap(
            israid=wallet.pre,
            regid=rip.said,
            attribute=dict(d="", name="forked-history"),
        )
        first_blinder = Blinder.blind(acdc=acdc.said, state="issued", salt=SALT, sn=1)
        first = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=first_blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        second_blinder = Blinder.blind(
            acdc=acdc.said,
            state="revoked",
            salt=Salter(raw=b"fedcba9876543210").qb64,
            sn=1,
        )
        second = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=second_blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        _anchor(wallet, rip, first, second)
        kel = _kelClone(wallet)
        regk = rip.said

    with openHby(
        name="kf-reg-fork-host", base="test", temp=True, version=Vrsn_2_0
    ) as hby:
        hby.makeHab(name="registrar")
        ctx = makeContext(hby=hby, alias="registrar", observers=[])
        try:
            inner = testing.TestClient(ctx.internalApp)
            accepted = inner.simulate_post(
                "/ingest", json=dict(kel=kel, tel=_telStream(rip, first).decode())
            )
            assert accepted.status == falcon.HTTP_200
            assert regk in accepted.json["accepted"]

            conflict = inner.simulate_post(
                "/ingest", json=dict(kel="", tel=_telStream(rip, second).decode())
            )
            assert regk in conflict.json["rejected"]
            assert ctx.rgy.store.seqEvent(regk, 1).said == first.said
            assert ctx.rgy.store.headEvent(regk).said == first.said
            assert ctx.rgy.store.cloneTel(regk) == _telStream(rip, first)
        finally:
            ctx.rgy.close()

    with openHby(
        name="kf-reg-fork-reverse-host", base="test", temp=True, version=Vrsn_2_0
    ) as hby:
        hby.makeHab(name="registrar")
        ctx = makeContext(hby=hby, alias="registrar", observers=[])
        try:
            inner = testing.TestClient(ctx.internalApp)
            accepted = inner.simulate_post(
                "/ingest", json=dict(kel=kel, tel=_telStream(rip, second).decode())
            )
            assert regk in accepted.json["accepted"]

            conflict = inner.simulate_post(
                "/ingest", json=dict(kel="", tel=_telStream(rip, first).decode())
            )
            assert regk in conflict.json["rejected"]
            assert ctx.rgy.store.seqEvent(regk, 1).said == second.said
            assert ctx.rgy.store.headEvent(regk).said == second.said
            assert ctx.rgy.store.cloneTel(regk) == _telStream(rip, second)
        finally:
            ctx.rgy.close()


def test_controller_ingest_replay_preserves_latest_and_accepts_forward_progress():
    """Replaying older anchored TEL keeps the head monotonic; newer TEL advances it."""
    with openHab(name="kf-reg-replay", temp=True, version=Vrsn_2_0) as (_whby, wallet):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        acdc = acdcmap(
            israid=wallet.pre,
            regid=rip.said,
            attribute=dict(d="", name="monotonic-history"),
        )

        def update(prior, sn, state):
            blinder = Blinder.blind(acdc=acdc.said, state=state, salt=SALT, sn=sn)
            return blindate(
                regid=rip.said,
                prior=prior,
                blid=blinder.said,
                sn=sn,
                stamp=STAMP1,
            )

        first = update(rip.said, 1, "issued")
        second = update(first.said, 2, "revoked")
        third = update(second.said, 3, "reinstated")
        _anchor(wallet, rip, first, second, third)
        kel = _kelClone(wallet)
        regk = rip.said

    with openHby(
        name="kf-reg-replay-host", base="test", temp=True, version=Vrsn_2_0
    ) as hby:
        hby.makeHab(name="registrar")
        ctx = makeContext(hby=hby, alias="registrar", observers=[])
        try:
            inner = testing.TestClient(ctx.internalApp)
            initial = inner.simulate_post(
                "/ingest",
                json=dict(kel=kel, tel=_telStream(rip, first, second).decode()),
            )
            assert regk in initial.json["accepted"]
            assert ctx.rgy.store.headEvent(regk).said == second.said

            replay = inner.simulate_post(
                "/ingest", json=dict(kel="", tel=_telStream(rip, first).decode())
            )
            assert regk in replay.json["accepted"]
            assert ctx.rgy.store.headEvent(regk).said == second.said
            assert ctx.rgy.store.cloneTel(regk) == _telStream(rip, first, second)

            advanced = inner.simulate_post(
                "/ingest",
                json=dict(kel="", tel=_telStream(rip, first, second, third).decode()),
            )
            assert regk in advanced.json["accepted"]
            assert ctx.rgy.store.headEvent(regk).said == third.said
        finally:
            ctx.rgy.close()


def test_controller_pending_tel_survives_restart_and_recovers_when_kel_arrives(
    tmp_path,
):
    """Missing-anchor TEL is durable and retries after a registrar restart."""
    with openHab(name="kf-reg-restart-wallet", temp=True, version=Vrsn_2_0) as (
        _whby,
        wallet,
    ):
        rip = regcept(israid=wallet.pre, stamp=STAMP0)
        acdc = acdcmap(
            israid=wallet.pre,
            regid=rip.said,
            attribute=dict(d="", name="restart-pending"),
        )
        blinder = Blinder.blind(acdc=acdc.said, state="issued", salt=SALT, sn=1)
        bup = blindate(
            regid=rip.said,
            prior=rip.said,
            blid=blinder.said,
            sn=1,
            stamp=STAMP1,
        )
        _anchor(wallet, rip, bup)
        kel = _kelClone(wallet)
        tel = _telStream(rip, bup)
        regk = rip.said

    def openRestartHby():
        return openHby(
            name="kf-reg-restart-host",
            base="test",
            temp=False,
            headDirPath=str(tmp_path),
            cf=Configer(
                name="kf-reg-restart-host",
                base="test",
                temp=True,
                headDirPath=str(tmp_path),
            ),
            salt=SALT,
            version=Vrsn_2_0,
        )

    with openRestartHby() as hby:
        hby.makeHab(name="registrar")
        baser = RegBaser(
            name=hby.name, base=hby.base, temp=False, headDirPath=str(tmp_path)
        )
        rgy = Regery(hby=hby, name=hby.name, base=hby.base, baser=baser)
        ingester = ControllerIngester(
            hby=hby,
            store=rgy.store,
            kvy=Kevery(db=hby.db, lax=True, local=False),
        )
        try:
            pending = ingester.ingest(b"", tel)
            assert regk in pending["pending"]
            assert rgy.store.head(regk) is None
            assert list(rgy.store.baser.maes.getTopItemIter(keys=regk))
        finally:
            rgy.close()

    with openRestartHby() as hby:
        baser = RegBaser(
            name=hby.name, base=hby.base, temp=False, headDirPath=str(tmp_path)
        )
        rgy = Regery(hby=hby, name=hby.name, base=hby.base, baser=baser)
        ingester = ControllerIngester(
            hby=hby,
            store=rgy.store,
            kvy=Kevery(db=hby.db, lax=True, local=False),
        )
        try:
            assert regk in ingester.pending
            # The process restart must reconstruct pending event bodies from
            # the database escrow. Once the KEL arrives, Context's normal
            # escrow cycle retries that recovered batch.
            ingestKel(ingester.kvy, kel)
            ctx = Context(
                hby=hby,
                hab=hby.habByName(name="registrar"),
                rgy=rgy,
                kvy=ingester.kvy,
                observers=[],
            )
            escrowDo = ctx.escrowDo(tymth=lambda: 0.0, tock=0.1)
            next(escrowDo)
            next(escrowDo)
            assert rgy.store.headEvent(regk).said == bup.said
            assert rgy.store.cloneTel(regk) == tel
            assert not list(rgy.store.baser.maes.getTopItemIter(keys=regk))
        finally:
            rgy.close()


def test_external_api_has_no_ingest_route():
    """Controller ingest is admin-only; external API has no write path."""
    with openHby(name="kf-reg-no-ingest", base="test", temp=True, version=Vrsn_2_0) as hby:
        hby.makeHab(name="registrar")
        ctx = makeContext(hby=hby, alias="registrar", observers=[])
        try:
            outer = testing.TestClient(ctx.externalApp)
            response = outer.simulate_post(
                "/ingest",
                json=dict(kel="", tel=""),
            )
            assert response.status == falcon.HTTP_404
        finally:
            ctx.rgy.close()
