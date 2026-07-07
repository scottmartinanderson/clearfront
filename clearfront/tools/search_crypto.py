# clearfront/tools/search_crypto.py
"""
Cryptocurrency address OSINT module.

Given a Bitcoin or Ethereum address (the kind a footprint can surface in a bio,
paste, or profile), validates and labels it, then fetches a keyless public
on-chain summary: balance, transaction count, and total received. An address
with real on-chain activity is a strong, durable footprint pivot.

Passive and keyless: Bitcoin via Blockstream's public Esplora API, Ethereum via
a public JSON-RPC endpoint. Returns a formatted string; never raises.
"""

from __future__ import annotations

import asyncio
import logging
import re

import aiohttp

logger = logging.getLogger(__name__)

_BTC_API = "https://blockstream.info/api/address/{addr}"
_ETH_RPC = "https://ethereum-rpc.publicnode.com"
_DEFAULT_TIMEOUT = 15
_HEADERS = {"User-Agent": "CLEARFRONT-OSINT", "Accept": "application/json"}

_ETH_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BTC_BECH32_RE = re.compile(r"^bc1[0-9ac-hj-np-z]{8,71}$")
_BTC_BASE58_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")


def _detect(address: str) -> str | None:
    """Return 'eth', 'btc', or None for the address format."""
    a = address.strip()
    if _ETH_RE.match(a):
        return "eth"
    if _BTC_BECH32_RE.match(a) or _BTC_BASE58_RE.match(a):
        return "btc"
    return None


def _fmt_amount(value: float, unit: str) -> str:
    """Trim trailing zeros from a coin amount."""
    s = f"{value:.8f}".rstrip("0").rstrip(".")
    return f"{s or '0'} {unit}"


async def _fetch_btc(address: str, timeout: int) -> str:
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=timeout_cfg, headers=_HEADERS) as session:
        async with session.get(_BTC_API.format(addr=address)) as resp:
            if resp.status == 400:
                raise ValueError("not a valid Bitcoin address.")
            if resp.status != 200:
                raise ValueError(f"Blockstream returned HTTP {resp.status}.")
            data = await resp.json(content_type=None)
    cs = data.get("chain_stats", {}) or {}
    funded = cs.get("funded_txo_sum", 0)
    spent = cs.get("spent_txo_sum", 0)
    tx_count = cs.get("tx_count", 0)
    balance = (funded - spent) / 1e8
    received = funded / 1e8
    lines = [
        f"Bitcoin address '{address}':",
        "",
        f"[+] Balance: {_fmt_amount(balance, 'BTC')}",
        f"[+] Total received: {_fmt_amount(received, 'BTC')}",
        f"[+] Transactions: {tx_count}",
    ]
    if tx_count == 0:
        lines.append("[i] No on-chain activity: address is valid but unused (or never funded).")
    lines += ["", f"Explorer: https://blockstream.info/address/{address}",
              "Source: Blockstream public API (on-chain, factual)."]
    return "\n".join(lines)


async def _eth_rpc(session: aiohttp.ClientSession, method: str, params: list) -> str:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    async with session.post(_ETH_RPC, json=payload) as resp:
        if resp.status != 200:
            raise ValueError(f"Ethereum RPC returned HTTP {resp.status}.")
        data = await resp.json(content_type=None)
    if "error" in data:
        raise ValueError(f"Ethereum RPC error: {data['error'].get('message', 'unknown')}.")
    return data.get("result", "0x0")


async def _fetch_eth(address: str, timeout: int) -> str:
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=timeout_cfg, headers=_HEADERS) as session:
        bal_hex, nonce_hex = await asyncio.gather(
            _eth_rpc(session, "eth_getBalance", [address, "latest"]),
            _eth_rpc(session, "eth_getTransactionCount", [address, "latest"]),
        )
    balance = int(bal_hex, 16) / 1e18
    nonce = int(nonce_hex, 16)
    lines = [
        f"Ethereum address '{address}':",
        "",
        f"[+] Balance: {_fmt_amount(balance, 'ETH')}",
        f"[+] Transactions sent (nonce): {nonce}",
    ]
    if nonce == 0 and balance == 0:
        lines.append("[i] No outbound activity and zero balance: address is valid but appears unused.")
    lines += ["", f"Explorer: https://etherscan.io/address/{address}",
              "Source: public Ethereum JSON-RPC (on-chain, factual). Nonce counts sent transactions only."]
    return "\n".join(lines)


async def run_crypto_osint(
    address: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Validate a BTC/ETH address and return a keyless on-chain summary.

    Returns a descriptive error string on failure rather than raising.

    Parameters
    ----------
    address:
        A Bitcoin (legacy/P2SH/bech32) or Ethereum (0x...) address.
    timeout_seconds:
        HTTP request timeout in seconds.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    address = (address or "").strip()
    kind = _detect(address)
    if kind is None:
        return "Error: not a recognized Bitcoin or Ethereum address."
    logger.info("Starting crypto lookup (%s) for: %s", kind, address)
    try:
        if kind == "btc":
            return await _fetch_btc(address, timeout_seconds)
        return await _fetch_eth(address, timeout_seconds)
    except asyncio.TimeoutError:
        return f"Scan error: crypto lookup timed out after {timeout_seconds}s."
    except aiohttp.ClientError as exc:
        return f"Scan error: network error during crypto lookup: {exc}"
    except ValueError as exc:
        return f"Scan error: {exc}"
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during crypto lookup.")
        return f"Internal error: {exc}"
