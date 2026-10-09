# -*- encoding: utf-8 -*-
"""
Controller ingest of pre-built, KEL-anchored TEL events for hosting.
"""

from collections import defaultdict

from keri import Vrsn_2_0, help
from keri.acdc import regeventing
from keri.core import Number, Parser, SerderACDC
from keri.core.coring import Saider
from keri.kering import MissingAnchorError, ValidationError


logger = help.ogler.getLogger()


def _acceptTelChain(store, regk, chain):
    """Persist a verified chain without replacing slots or regressing its head."""
    sequenced = [(Number(numh=serder.sad["n"]).num, serder) for serder in chain]
    for sn, serder in sequenced:
        current = store.seqEvent(regk, sn)
        if current is not None and current.said != serder.said:
            return f"conflicting TEL event at registry {regk} sequence {sn}"

    for sn, serder in sequenced:
        if store.seqEvent(regk, sn) is not None:
            continue

        # Keep valid historical gaps queryable while only moving the head
        # forward. RegistryStore.accept pins the head unconditionally.
        store.putEvent(serder)
        store.baser.tels.put(keys=regk, on=sn, val=Saider(qb64=serder.said))
        head = store.headEvent(regk)
        if head is None or sn > Number(numh=head.sad["n"]).num:
            store.baser.heads.pin(keys=regk, val=Saider(qb64=serder.said))
    return None


def parseTelStream(stream):
    """Parse concatenated CESR TEL event bodies into SerderACDC instances.

    Parameters:
        stream (bytes | bytearray): concatenated ``rip`` / ``bup`` bodies.

    Returns:
        list[SerderACDC]: parsed events in stream order.
    """
    ims = bytearray(stream or b"")
    events = []
    while ims:
        serder = SerderACDC(raw=ims)
        events.append(serder)
        del ims[: serder.size]
    return events


def groupTelEvents(events):
    """Group parsed TEL events by registry SAID.

    Parameters:
        events (Iterable[SerderACDC]): parsed TEL events in any order.

    Returns:
        dict[str, tuple[SerderACDC | None, list[SerderACDC]]]:
            registry SAID -> (rip or None, list of bup events).
    """
    groups = defaultdict(lambda: [None, []])
    for serder in events:
        if serder.ilk == "rip":
            regk = serder.said
            groups[regk][0] = serder
        elif serder.ilk == "bup":
            regk = serder.sad["rd"]
            groups[regk][1].append(serder)
        else:
            raise ValidationError(
                f"unsupported TEL event ilk {serder.ilk} in controller ingest"
            )
    return {regk: (rip, updates) for regk, (rip, updates) in groups.items()}


def _asBytes(value):
    """Coerce CESR text or bytes to bytes."""
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return value.encode("utf-8")


def ingestKel(kvy, kel):
    """Parse a CESR KEL stream into the registrar Kevery / Habery Baser.

    Parameters:
        kvy (Kevery): registrar key-event processor bound to hby.db.
        kel (bytes | bytearray | str): signed KEL clone for the TEL issuer.

    Returns:
        None
    """
    ims = bytearray(_asBytes(kel))
    if not ims:
        return
    Parser(version=Vrsn_2_0).parse(ims=ims, kvy=kvy)
    kvy.processEscrows()


def hostedRegistrySaids(store):
    """Return registry SAIDs that have an accepted head in the store.

    Parameters:
        store (RegistryStore): registrar TEL store.

    Returns:
        list[str]: registry SAIDs with verified heads.
    """
    saids = []
    for (regk,), _saider in store.baser.heads.getTopItemIter():
        saids.append(regk if isinstance(regk, str) else regk.decode("utf-8"))
    return saids


def knownRegistry(store, rgy, regk):
    """True when regk is locally managed or has a hosted accepted head."""
    return regk in rgy.regs or store.head(regk) is not None


def allRegistrySaids(store, rgy):
    """Union of locally managed and hosted registry SAIDs."""
    return sorted(set(rgy.regs.keys()) | set(hostedRegistrySaids(store)))


class ControllerIngester:
    """Verify and host remotely anchored TEL events for observer bulk pull.

    Does not require the TEL issuer AID to be a Hab in this Habery. KEL
    material must be present in ``hby.db`` (via ``ingestKel``) before
    ``regeventing.vet`` can accept anchors.
    """

    def __init__(self, hby, store, kvy):
        """
        Parameters:
            hby (Habery): habitat whose Baser holds issuer KELs for ``vet``.
            store (RegistryStore): registrar TEL store.
            kvy (Kevery): key-event processor for KEL intake.
        """
        self.hby = hby
        self.store = store
        self.kvy = kvy
        # Pending batches awaiting issuer KEL anchors: regk -> (rip, updates)
        self.pending = self._restorePending()

    def _restorePending(self):
        """Rebuild retry batches from durable missing-anchor escrow rows."""
        escrowed = defaultdict(dict)
        for keys, sn, said in self.store.baser.maes.getTopItemIter():
            regk = keys[0] if isinstance(keys, tuple) else keys
            if isinstance(regk, bytes):
                regk = regk.decode("utf-8")
            serder = self.store.event(said)
            if serder is not None:
                escrowed[regk][serder.said] = (sn, serder)

        pending = {}
        for regk, events in escrowed.items():
            ordered = sorted(events.values(), key=lambda pair: pair[0])
            rip = next((serder for _sn, serder in ordered if serder.ilk == "rip"), None)
            if rip is not None:
                updates = [serder for _sn, serder in ordered if serder.ilk == "bup"]
                pending[regk] = (rip, updates)
        return pending

    def ingest(self, kel, tel):
        """Ingest issuer KEL then verify and store TEL events.

        Parameters:
            kel (bytes | bytearray | str): signed KEL clone for TEL issuer(s).
            tel (bytes | bytearray | str): concatenated ``rip`` / ``bup`` CESR.

        Returns:
            dict: summary with keys ``accepted``, ``pending``, ``rejected``
                mapping registry SAID to event counts or error strings.
        """
        summary = dict(accepted={}, pending={}, rejected={})
        try:
            ingestKel(self.kvy, kel)
        except Exception as ex:
            logger.info("controller ingest KEL parse failed: %s", ex)
            summary["rejected"]["kel"] = str(ex)
            return summary

        try:
            events = parseTelStream(_asBytes(tel))
            groups = groupTelEvents(events)
        except Exception as ex:
            logger.info("controller ingest TEL parse failed: %s", ex)
            summary["rejected"]["*"] = str(ex)
            return summary

        if not groups:
            summary["rejected"]["*"] = "empty TEL stream"
            return summary

        for regk, (rip, updates) in groups.items():
            result = self._ingestRegistry(regk, rip, updates)
            summary[result[0]][regk] = result[1]
        return summary

    def retryPending(self):
        """Re-attempt ``vet`` for batches waiting on missing KEL anchors.

        Returns:
            dict: same shape as ``ingest`` summary for registries that moved.
        """
        summary = dict(accepted={}, pending={}, rejected={})
        for regk in list(self.pending):
            rip, updates = self.pending[regk]
            result = self._ingestRegistry(regk, rip, updates)
            summary[result[0]][regk] = result[1]
        return summary

    def _ingestRegistry(self, regk, rip, updates):
        """Verify one registry batch and accept or escrow it.

        Returns:
            tuple[str, object]: (bucket, detail) where bucket is one of
            ``accepted``, ``pending``, ``rejected``.
        """
        if rip is None:
            msg = f"TEL stream missing rip for registry {regk}"
            logger.info(msg)
            self.pending.pop(regk, None)
            return "rejected", msg

        try:
            regeventing.vet(rip=rip, updates=updates, db=self.hby.db)
        except MissingAnchorError as ex:
            self.pending[regk] = (rip, list(updates))
            self.store.putEvent(rip)
            self.store.escrowMissingAnchor(regk, 0, rip.said)
            for bup in updates:
                sn = Number(numh=bup.sad["n"]).num
                self.store.putEvent(bup)
                self.store.escrowMissingAnchor(regk, sn, bup.said)
            logger.info(
                "controller ingest escrow registry %s pending KEL anchor: %s",
                regk,
                ex,
            )
            return "pending", len(updates) + 1
        except ValidationError as ex:
            self.pending.pop(regk, None)
            for serder in [rip] + list(updates):
                sn = Number(numh=serder.sad["n"]).num
                self.store.clearEscrows(regk, sn, serder.said)
            logger.info("controller ingest rejected registry %s: %s", regk, ex)
            return "rejected", str(ex)

        chain = [rip] + sorted(updates, key=lambda s: Number(numh=s.sad["n"]).num)
        conflict = _acceptTelChain(self.store, regk, chain)
        if conflict is not None:
            self.pending.pop(regk, None)
            for serder in chain:
                sn = Number(numh=serder.sad["n"]).num
                self.store.clearEscrows(regk, sn, serder.said)
            logger.info("controller ingest rejected registry %s: %s", regk, conflict)
            return "rejected", conflict
        for serder in chain:
            sn = Number(numh=serder.sad["n"]).num
            self.store.clearEscrows(regk, sn, serder.said)
        self.pending.pop(regk, None)
        return "accepted", len(chain)
