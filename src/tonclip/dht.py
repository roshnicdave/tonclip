from __future__ import annotations

import asyncio
import copy
import hmac
import json
import os
import sys
import time
import warnings
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from importlib import resources

warnings.filterwarnings(
    "ignore",
    message="urllib3 v2 only supports OpenSSL 1.1.1+",
)

from pytoniq.adnl.adnl import AdnlTransport
from pytoniq.adnl.dht import DhtClient, DhtNode
from pytoniq_core.crypto.ciphers import Client
from pytoniq_core.crypto.signature import verify_sign

from .protocol import RECORD_SIZE, ClipKey

DHT_KEY_NAME = b"tonclip.v1"
K = 6
ALPHA = 3
MINIMUM_COPIES = 3
LOOKUP_WINDOW = K * 3
MAX_QUERIES = 48
WALK_TIMEOUT = 20
NODE_TIMEOUT = 4
MAX_DHT_TTL = 3660


class DhtError(RuntimeError):
    pass


class ClipNotFound(DhtError):
    pass


class InvalidDhtValue(DhtError):
    pass


class Session:
    def __init__(self, transport: AdnlTransport, client: DhtClient):
        self.transport = transport
        self.client = client
        self.nodes: dict[bytes, DhtNode] = {
            node.key_id: node for node in client.nodes_set
        }

    async def walk(
        self, key_id: bytes, clip_key: ClipKey | None = None
    ) -> tuple[dict | None, list[DhtNode]]:
        queried: set[bytes] = set()
        responded: set[bytes] = set()
        deadline = time.monotonic() + WALK_TIMEOUT

        while time.monotonic() < deadline and len(queried) < MAX_QUERIES:
            ordered = self._ordered(self.nodes.values(), key_id)
            pending = [node for node in ordered if node.key_id not in queried]
            if not pending:
                break
            batch = pending[:ALPHA]
            queried.update(node.key_id for node in batch)
            responses = await asyncio.gather(
                *(self._query(node, key_id) for node in batch)
            )

            for node, response in zip(batch, responses):
                if response is None:
                    _debug(f"query {node.key_id.hex()[:8]} failed")
                    continue
                responded.add(node.key_id)
                kind = response.get("@type")
                _debug(f"query {node.key_id.hex()[:8]} returned {kind}")
                if kind == "dht.valueFound":
                    if clip_key is None:
                        continue
                    try:
                        value = validate_value(
                            self.client, response.get("value"), clip_key, key_id
                        )
                    except InvalidDhtValue as exc:
                        _debug(f"rejected value from {node.key_id.hex()[:8]}: {exc}")
                        continue
                    return value, self._ordered(self.nodes.values(), key_id)
                if kind != "dht.valueNotFound":
                    continue
                self._add_nodes(response.get("nodes", {}).get("nodes", []))

            closest = self._ordered(self.nodes.values(), key_id)[:LOOKUP_WINDOW]
            if (
                len(responded) >= LOOKUP_WINDOW
                and closest
                and all(node.key_id in queried for node in closest)
            ):
                break

        return None, self._ordered(self.nodes.values(), key_id)

    async def store(self, value: dict, nodes: Iterable[DhtNode]) -> int:
        copies = 0
        candidates = list(nodes)
        for offset in range(0, min(len(candidates), LOOKUP_WINDOW), ALPHA):
            batch = candidates[offset : offset + ALPHA]
            results = await asyncio.gather(
                *(self._store_one(node, value) for node in batch)
            )
            copies += sum(results)
            _debug(f"store batch accepted {sum(results)}/{len(batch)}")
            if copies >= K:
                break
        return copies

    async def _query(self, node: DhtNode, key_id: bytes) -> dict | None:
        try:
            if not node.connected:
                await asyncio.wait_for(node.connect(), NODE_TIMEOUT)
            response = await asyncio.wait_for(
                node.find_value(key=key_id, k=K), NODE_TIMEOUT
            )
            return response[0]
        except Exception as exc:  # noqa: BLE001 - one bad peer must not abort a DHT walk
            _debug(f"query {node.key_id.hex()[:8]} error: {exc}")
            return None

    async def _store_one(self, node: DhtNode, value: dict) -> int:
        try:
            if not node.connected:
                await asyncio.wait_for(node.connect(), NODE_TIMEOUT)
            response = await asyncio.wait_for(node.store_value(value), NODE_TIMEOUT)
            return int(bool(response and response[0].get("@type") == "dht.stored"))
        except Exception as exc:  # noqa: BLE001 - try the next replica on any peer failure
            _debug(f"store {node.key_id.hex()[:8]} error: {exc}")
            return 0

    def _add_nodes(self, raw_nodes: Iterable[dict]) -> None:
        added = 0
        for raw in raw_nodes:
            try:
                node = DhtNode.from_dict(self.transport, copy.deepcopy(raw), True)
            except Exception as exc:  # noqa: BLE001 - discovered nodes are untrusted
                _debug(f"ignored discovered node: {exc}")
                continue
            if node.key_id not in self.nodes:
                self.nodes[node.key_id] = node
                self.client.nodes_set.add(node)
                added += 1
        _debug(f"added {added} discovered nodes; {len(self.nodes)} known")

    @staticmethod
    def _ordered(nodes: Iterable[DhtNode], key_id: bytes) -> list[DhtNode]:
        target = int.from_bytes(key_id, "big")
        return sorted(
            nodes,
            key=lambda node: int.from_bytes(node.key_id, "big") ^ target,
        )


@asynccontextmanager
async def open_session() -> AsyncIterator[Session]:
    transport = AdnlTransport(timeout=NODE_TIMEOUT)
    await transport.start()
    client = None
    try:
        client = DhtClient.from_config(_load_config(), transport)
        yield Session(transport, client)
    finally:
        try:
            if client is not None:
                await client.close()
        finally:
            await transport.close()


async def put(payload: bytes, ttl: int) -> tuple[str, int, int]:
    clip_key = ClipKey.generate()
    record = clip_key.encrypt(payload)
    expires_at = int(time.time()) + ttl

    async with open_session() as session:
        key_id = _key_id(session.client, clip_key)
        _, nearest = await session.walk(key_id)
        value = build_value(session.client, clip_key, record, expires_at)
        copies = await session.store(value, nearest)
    if copies < MINIMUM_COPIES:
        raise DhtError(
            f"TON DHT accepted only {copies} copies; need at least {MINIMUM_COPIES}"
        )

    found, found_expiry = await fetch(clip_key)
    if not hmac.compare_digest(record, found):
        raise DhtError("fresh DHT client returned different data")
    return str(clip_key), found_expiry, copies


async def get(key: str) -> tuple[bytes, int]:
    clip_key = ClipKey.parse(key)
    record, expires_at = await fetch(clip_key)
    return clip_key.decrypt(record), expires_at


async def fetch(clip_key: ClipKey) -> tuple[bytes, int]:
    async with open_session() as session:
        key_id = _key_id(session.client, clip_key)
        value, _ = await session.walk(key_id, clip_key)
    if value is None:
        raise ClipNotFound(
            "clip not found; it may have expired or not reached this part of the DHT"
        )
    return value["value"], int(value["ttl"])


def build_value(
    client: DhtClient,
    clip_key: ClipKey,
    record: bytes,
    expires_at: int,
) -> dict:
    signer = Client(ed25519_private_key=clip_key.signing_seed())
    owner_id = signer.get_key_id()
    key = client.get_dht_key(owner_id, name=DHT_KEY_NAME, idx=0)
    description = {
        "key": key,
        "id": {
            "@type": "pub.ed25519",
            "key": signer.ed25519_public.encode().hex(),
        },
        "update_rule": client.schemas.get_by_name(
            "dht.updateRule.signature"
        ).little_id(),
        "signature": b"",
    }
    description["signature"] = signer.sign(
        client.schemas.serialize(
            client.schemas.get_by_name("dht.keyDescription"), description
        )
    )
    value = {
        "key": description,
        "value": record,
        "ttl": expires_at,
        "signature": b"",
    }
    value["signature"] = signer.sign(
        client.schemas.serialize(client.schemas.get_by_name("dht.value"), value)
    )
    return value


def validate_value(
    client: DhtClient,
    value: object,
    clip_key: ClipKey,
    expected_key_id: bytes,
) -> dict:
    if not isinstance(value, dict):
        raise InvalidDhtValue("malformed DHT value")
    description = value.get("key")
    if not isinstance(description, dict):
        raise InvalidDhtValue("missing key description")

    signer = Client(ed25519_private_key=clip_key.signing_seed())
    owner_id = signer.get_key_id()
    public_key = signer.ed25519_public.encode()
    key = description.get("key")
    identity = description.get("id")
    update_rule = description.get("update_rule")
    if not isinstance(key, dict) or not isinstance(identity, dict):
        raise InvalidDhtValue("malformed key description")
    if _as_bytes(key.get("id")) != owner_id:
        raise InvalidDhtValue("wrong DHT owner id")
    if key.get("name") != DHT_KEY_NAME or key.get("idx") != 0:
        raise InvalidDhtValue("wrong DHT key")
    if client.get_dht_key_id_tl(owner_id, DHT_KEY_NAME, 0) != expected_key_id:
        raise InvalidDhtValue("wrong DHT key hash")
    if identity.get("@type") != "pub.ed25519":
        raise InvalidDhtValue("wrong DHT identity type")
    if _as_bytes(identity.get("key")) != public_key:
        raise InvalidDhtValue("wrong DHT public key")
    if (
        not isinstance(update_rule, dict)
        or update_rule.get("@type") != "dht.updateRule.signature"
    ):
        raise InvalidDhtValue("wrong DHT update rule")

    description_signature = description.get("signature")
    if not isinstance(description_signature, bytes) or len(description_signature) != 64:
        raise InvalidDhtValue("missing key-description signature")
    unsigned_description = copy.deepcopy(description)
    unsigned_description["signature"] = b""
    description_bytes = client.schemas.serialize(
        client.schemas.get_by_name("dht.keyDescription"), unsigned_description
    )
    if not verify_sign(public_key, description_bytes, description_signature):
        raise InvalidDhtValue("bad key-description signature")

    signature = value.get("signature")
    record = value.get("value")
    ttl = value.get("ttl")
    now = int(time.time())
    if not isinstance(signature, bytes) or not isinstance(record, bytes):
        raise InvalidDhtValue("malformed signed value")
    if len(signature) != 64:
        raise InvalidDhtValue("malformed DHT value signature")
    if len(record) != RECORD_SIZE:
        raise InvalidDhtValue("wrong record size")
    if not isinstance(ttl, int) or ttl <= now or ttl > now + MAX_DHT_TTL:
        raise InvalidDhtValue("expired or invalid DHT lifetime")
    unsigned_value = copy.deepcopy(value)
    unsigned_value["signature"] = b""
    value_bytes = client.schemas.serialize(
        client.schemas.get_by_name("dht.value"), unsigned_value
    )
    if not verify_sign(public_key, value_bytes, signature):
        raise InvalidDhtValue("bad DHT value signature")
    return value


def _key_id(client: DhtClient, clip_key: ClipKey) -> bytes:
    signer = Client(ed25519_private_key=clip_key.signing_seed())
    return client.get_dht_key_id_tl(signer.get_key_id(), DHT_KEY_NAME, 0)


def _as_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError as exc:
            raise InvalidDhtValue("invalid hex value") from exc
    raise InvalidDhtValue("expected bytes")


def _load_config() -> dict:
    path = os.environ.get("TONCLIP_CONFIG")
    try:
        if path:
            with open(path, "r", encoding="utf-8") as config_file:
                config = json.load(config_file)
        else:
            with resources.open_text(
                "tonclip", "global.config.json", encoding="utf-8"
            ) as config_file:
                config = json.load(config_file)
    except (OSError, ValueError) as exc:
        raise DhtError(f"cannot load TON global config: {exc}") from exc
    nodes = config.get("dht", {}).get("static_nodes", {}).get("nodes", [])
    if not nodes:
        raise DhtError("TON global config has no DHT bootstrap nodes")
    return config


def _debug(message: str) -> None:
    if os.environ.get("TONCLIP_DEBUG"):
        print(f"tonclip debug: {message}", file=sys.stderr)
