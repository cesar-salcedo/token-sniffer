#!/usr/bin/env python3
"""
Token Sniffer
=============
Escanea criptoactivos de capitalización baja, baja-media y media en varios
sectores, cruza datos de mercado, fundamentales on-chain y seguridad de
contratos, y selecciona las 16 monedas más interesantes por motivos distintos.

Fuentes (todas públicas, sin clave):
  - CoinGecko      precios, capitalización, volumen, suministro, ATH, sectores,
                   tendencias y atención (usuarios que siguen el token)
  - DefiLlama      TVL, comisiones e ingresos de protocolos y cadenas
  - GoPlus         auditoría automática del contrato (honeypot, mint, tasas,
                   propietario, concentración de holders)
  - DexScreener    liquidez on-chain, antigüedad de pools, presión compradora

Uso:
  python3 sniffer.py                 # escanea y genera dist/index.html
  python3 sniffer.py --no-cache      # ignora la caché local
  python3 sniffer.py --build-only    # regenera la interfaz con el último escaneo
  python3 sniffer.py serve           # interfaz en http://localhost:8000 con botón de re-escaneo

Solo usa la librería estándar de Python 3.9+.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import math
import os
import re
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(ROOT, ".cache")
DATA_DIR = os.path.join(ROOT, "data")
DIST_DIR = os.path.join(ROOT, "dist")
TEMPLATE = os.path.join(ROOT, "ui", "template.html")

CG = "https://api.coingecko.com/api/v3"
LLAMA = "https://api.llama.fi"
GOPLUS = "https://api.gopluslabs.io/api/v1"
DEXS = "https://api.dexscreener.com"
HONEYPOT = "https://api.honeypot.is/v2"
RUGCHECK = "https://api.rugcheck.xyz/v1"
HISTORY_DIR = os.path.join(DATA_DIR, "history")
TRACK_DAYS = 120          # días durante los que se siguen los precios de cada selección
HORIZONS = (7, 30, 90)    # horizontes de evaluación de aciertos

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------

BUCKETS = [
    {"id": "baja", "label": "Baja cap", "range": "$15 M – $100 M",
     "min": 15e6, "max": 100e6, "quota": 6, "min_vol": 250e3},
    {"id": "baja_media", "label": "Baja-media", "range": "$100 M – $500 M",
     "min": 100e6, "max": 500e6, "quota": 5, "min_vol": 1e6},
    {"id": "media", "label": "Media cap", "range": "$500 M – $3.000 M",
     "min": 500e6, "max": 3e9, "quota": 5, "min_vol": 3e6},
]
TOTAL_PICKS = sum(b["quota"] for b in BUCKETS)  # 16
MAX_PER_SECTOR = 2
MAX_PER_ARCHETYPE = 2

# Orden = prioridad para asignar el sector principal (el más específico gana).
SECTORS = [
    {"id": "meme", "label": "Memes", "cats": ["meme-token"]},
    {"id": "ai", "label": "IA", "cats": ["artificial-intelligence"]},
    {"id": "depin", "label": "DePIN", "cats": ["depin"]},
    {"id": "rwa", "label": "RWA", "cats": ["real-world-assets-rwa"]},
    {"id": "privacy", "label": "Privacidad", "cats": ["privacy-coins"]},
    {"id": "gaming", "label": "Gaming", "cats": ["gaming"]},
    {"id": "oracle", "label": "Oráculos e interop", "cats": ["oracle", "interoperability"]},
    {"id": "data", "label": "Datos y storage", "cats": ["storage", "data-availability"]},
    {"id": "dex", "label": "DEX y derivados", "cats": ["decentralized-exchange", "decentralized-perpetuals"]},
    {"id": "lending", "label": "Lending", "cats": ["lending-borrowing"]},
    {"id": "defi", "label": "DeFi", "cats": ["decentralized-finance-defi"]},
    {"id": "l2", "label": "Layer 2 y ZK", "cats": ["layer-2", "zero-knowledge-zk"]},
    {"id": "l1", "label": "Layer 1", "cats": ["layer-1"]},
]
SECTOR_INDEX = {s["id"]: i for i, s in enumerate(SECTORS)}

# Categorías que no son "proyectos" invertibles en este sentido.
EXCLUDE_CATS = [
    "stablecoins", "yield-bearing-stablecoins", "wrapped-tokens", "bridged-tokens",
    "liquid-staking-tokens", "liquid-restaking-tokens", "exchange-based-tokens",
    "tokenized-products", "tokenized-stock", "tokenized-gold", "tokenized-btc",
    "xstocks-ecosystem", "bstocks-ecosystem", "ondo-tokenized-assets", "tokenized-exchange-traded-funds-etfs",
]
EXCLUDE_NAME = re.compile(
    r"\b(wrapped|bridged|staked|restaked|tokenized|\w*stock|etf\b|usd[a-z]?\b|gold\b|treasur)", re.I)

ARCHETYPES = [
    {"id": "tendencia", "label": "Tendencia sólida",
     "desc": "Sube con una tendencia limpia y sostenida sin estar sobrecalentado."},
    {"id": "infravalorado", "label": "Infravalorado",
     "desc": "Cotiza barato frente a lo que el protocolo tiene o genera: TVL, comisiones o ingresos."},
    {"id": "rebote", "label": "Rebote desde mínimos",
     "desc": "Muy lejos de su máximo histórico y empezando a girar al alza."},
    {"id": "acumulacion", "label": "Acumulación",
     "desc": "Volumen muy por encima de lo normal en su sector con el precio todavía lateral."},
    {"id": "crecimiento", "label": "Crecimiento on-chain",
     "desc": "Su TVL o sus comisiones crecen con fuerza: el uso real va por delante."},
    {"id": "ingresos", "label": "Genera ingresos",
     "desc": "El protocolo ingresa dinero real y su rendimiento sobre la capitalización es alto."},
    {"id": "fuerza", "label": "Fuerza relativa",
     "desc": "Lo hace mucho mejor que su propio sector y que bitcoin en el último mes."},
    {"id": "atencion", "label": "Atención emergente",
     "desc": "El interés del mercado (seguidores, tendencias) es alto para su tamaño."},
    {"id": "tokenomics", "label": "Tokenomics limpios",
     "desc": "Casi todo el suministro ya circula: poca dilución futura y base sólida."},
]
ARCH_INDEX = {a["id"]: a for a in ARCHETYPES}

# Categorías DefiLlama donde el TVL son depósitos de usuarios que no reflejan el valor del token
# (staking líquido, puentes, RWA tokenizados...): ahí el ratio capitalización/TVL engaña.
TVL_SKEW_CATS = {"Liquid Staking", "Liquid Restaking", "Restaking", "Bridge", "Canonical Bridge",
                 "Cross Chain Bridge", "Staking Pool", "CEX", "Basis Trading", "RWA", "Reserve Currency",
                 "Chain Bribes", "Restaked BTC", "Onchain Capital Allocator", "Risk Curators"}

WEIGHTS = {"momentum": 0.22, "valor": 0.18, "fundamentales": 0.12, "liquidez": 0.12,
           "tokenomics": 0.12, "atencion": 0.10, "seguridad": 0.14}

# Plataformas CoinGecko -> (id GoPlus, id DexScreener)
CHAINS = {
    "ethereum": ("1", "ethereum"),
    "base": ("8453", "base"),
    "binance-smart-chain": ("56", "bsc"),
    "arbitrum-one": ("42161", "arbitrum"),
    "solana": ("solana", "solana"),
    "polygon-pos": ("137", "polygon"),
    "avalanche": ("43114", "avalanche"),
    "optimistic-ethereum": ("10", "optimism"),
}
CHAIN_PRIORITY = list(CHAINS.keys())
HONEYPOT_CHAINS = {"1": "ethereum", "56": "bsc", "8453": "base"}  # cadenas que Honeypot.is simula

LOG_LOCK = threading.Lock()
STATUS_PATH = os.path.join(DATA_DIR, "status.json")


def log(msg: str) -> None:
    with LOG_LOCK:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def set_status(stage: str, progress: float, running: bool = True, error: str | None = None) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = STATUS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"running": running, "stage": stage, "progress": round(progress, 3),
                   "error": error, "at": time.time()}, f)
    os.replace(tmp, STATUS_PATH)


# ---------------------------------------------------------------------------
# HTTP con caché en disco y límite de ritmo por host
# ---------------------------------------------------------------------------

class Http:
    MIN_INTERVAL = {"api.coingecko.com": 2.6, "api.gopluslabs.io": 1.2, "api.honeypot.is": 1.0,
                    "api.rugcheck.xyz": 1.2, "api.dexscreener.com": 0.35, "api.llama.fi": 0.2}

    def __init__(self, use_cache: bool = True):
        self.use_cache = use_cache
        self.locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self.last: dict[str, float] = {}
        self.calls = Counter()
        self.errors = Counter()
        os.makedirs(CACHE_DIR, exist_ok=True)

    def get(self, url: str, ttl: float = 1200, retries: int = 6, quiet404: bool = True):
        key = hashlib.sha1(url.encode()).hexdigest()
        path = os.path.join(CACHE_DIR, key + ".json")
        if self.use_cache and os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
            try:
                with open(path) as f:
                    return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
        host = urllib.parse.urlparse(url).hostname or ""
        lock = self.locks[host]
        for attempt in range(retries):
            with lock:
                wait = self.MIN_INTERVAL.get(host, 0.2) - (time.time() - self.last.get(host, 0))
                if wait > 0:
                    time.sleep(wait)
                self.last[host] = time.time()
                try:
                    req = urllib.request.Request(url, headers={
                        "Accept": "application/json", "User-Agent": "token-sniffer/1.0"})
                    with urllib.request.urlopen(req, timeout=45) as r:
                        data = json.loads(r.read().decode("utf-8"))
                    self.calls[host] += 1
                    tmp = path + ".tmp"
                    with open(tmp, "w") as f:
                        json.dump(data, f)
                    os.replace(tmp, path)
                    return data
                except urllib.error.HTTPError as e:
                    if e.code in (404, 400) and quiet404:
                        self.errors[host] += 1
                        return None
                    if e.code == 429 or e.code >= 500:
                        backoff = min(75, 12 * (attempt + 1))
                        log(f"  {host}: HTTP {e.code}, reintento en {backoff}s")
                        time.sleep(backoff)  # dentro del lock: frena al resto de llamadas a ese host
                        continue
                    self.errors[host] += 1
                    log(f"  {host}: HTTP {e.code} en {url[:100]}")
                    return None
                except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as e:
                    log(f"  {host}: {type(e).__name__} {e}; reintento")
                    time.sleep(3 * (attempt + 1))
                    continue
        self.errors[host] += 1
        log(f"  {host}: sin respuesta tras {retries} intentos ({url[:100]})")
        return None


# ---------------------------------------------------------------------------
# Utilidades numéricas
# ---------------------------------------------------------------------------

def num(x):
    try:
        if x is None:
            return None
        v = float(x)
        return v if math.isfinite(v) else None
    except (TypeError, ValueError):
        return None


def clamp(x, lo=0.0, hi=100.0):
    return max(lo, min(hi, x))


class Ranker:
    """Percentil (0-100) de un valor dentro de una distribución."""

    def __init__(self, values):
        self.v = sorted(x for x in values if x is not None)

    def __call__(self, x):
        if x is None or not self.v:
            return None
        lo = bisect.bisect_left(self.v, x)
        hi = bisect.bisect_right(self.v, x)
        return 100.0 * ((lo + hi) / 2) / len(self.v)

    def median(self):
        return statistics.median(self.v) if self.v else None


def mean_present(values, weights=None):
    pairs = [(v, (weights[i] if weights else 1.0)) for i, v in enumerate(values) if v is not None]
    if not pairs:
        return None
    tw = sum(w for _, w in pairs)
    return sum(v * w for v, w in pairs) / tw


def trend_stats(prices):
    p = [x for x in (prices or []) if x and x > 0]
    if len(p) < 48:
        return None
    y = [math.log(v) for v in p]
    n = len(y)
    mx = (n - 1) / 2
    my = sum(y) / n
    sxx = sum((i - mx) ** 2 for i in range(n))
    sxy = sum((i - mx) * (y[i] - my) for i in range(n))
    slope = sxy / sxx
    ss_tot = sum((v - my) ** 2 for v in y)
    ss_res = sum((y[i] - (my + slope * (i - mx))) ** 2 for i in range(n))
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 0.0
    rets = [y[i] - y[i - 1] for i in range(1, n)]
    vol_daily = statistics.pstdev(rets) * math.sqrt(24) if len(rets) > 2 else None
    peak, mdd = p[0], 0.0
    for v in p:
        peak = max(peak, v)
        mdd = min(mdd, v / peak - 1)
    cv = statistics.pstdev(p) / statistics.mean(p)
    return {"slope7": math.exp(slope * (n - 1)) - 1, "r2": max(0.0, r2),
            "vol_daily": vol_daily, "mdd7": mdd, "cv": cv}


def downsample(prices, n=56):
    p = [x for x in (prices or []) if x is not None]
    if len(p) <= n:
        return p
    step = (len(p) - 1) / (n - 1)
    return [p[round(i * step)] for i in range(n)]


def liquidity_score(turnover):
    if not turnover or turnover <= 0:
        return 0.0
    lt = math.log10(turnover)
    if lt < -1.3:   # < 5 %
        return clamp(10 + (lt + 2.5) / 1.2 * 90, 0, 100)
    if lt <= -0.3:  # 5 % – 50 %
        return 100.0
    return clamp(100 - (lt + 0.3) / 0.8 * 80, 15, 100)  # > 50 %: sospecha creciente


def tokenomics_score(fdv_ratio, circ_ratio):
    s_fdv = None
    if fdv_ratio is not None:
        s_fdv = 100.0 if fdv_ratio <= 1.05 else clamp(100 - 35 * math.log2(fdv_ratio), 8, 100)
    s_circ = clamp(circ_ratio * 100) if circ_ratio is not None else None
    return mean_present([s_fdv, s_circ], [0.6, 0.4])


# ---------------------------------------------------------------------------
# Formato en español para los textos explicativos
# ---------------------------------------------------------------------------

def es_num(x, dec=1):
    s = f"{x:,.{dec}f}"
    return s.replace(",", "X").replace(".", ",").replace("X", ".")


def fmt_usd(x):
    if x is None:
        return "—"
    a = abs(x)
    if a >= 1e9:
        return f"${es_num(x / 1e9, 2)} mil M"
    if a >= 1e6:
        return f"${es_num(x / 1e6, 1)} M"
    if a >= 1e3:
        return f"${es_num(x / 1e3, 0)} mil"
    return f"${es_num(x, 2)}"


def fmt_pct(x, dec=0, sign=True):
    if x is None:
        return "—"
    s = es_num(x, dec)
    return (f"+{s}" if sign and x > 0 else s) + " %"


def fmt_x(x):
    return f"{es_num(x, 2 if x < 10 else 1)}×"


MONTHS = ["ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic"]


def fmt_date(iso):
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return f"{MONTHS[d.month - 1]} {d.year}"
    except (AttributeError, ValueError):
        return "—"


# ---------------------------------------------------------------------------
# 1. Recogida de datos
# ---------------------------------------------------------------------------

def fetch_category(http, cat, min_mcap, max_pages=4):
    out = []
    for page in range(1, max_pages + 1):
        url = (f"{CG}/coins/markets?vs_currency=usd&category={cat}&order=market_cap_desc"
               f"&per_page=250&page={page}&sparkline=true&price_change_percentage=24h,7d,30d,1y")
        data = http.get(url, ttl=1500)
        if not data:
            break
        out.extend(data)
        if len(data) < 250 or (num(data[-1].get("market_cap")) or 0) < min_mcap:
            break
    return out


def fetch_universe(http, progress):
    min_mcap = BUCKETS[0]["min"]
    coins: dict[str, dict] = {}
    cats = [(s["id"], c) for s in SECTORS for c in s["cats"]]
    for i, (sid, cat) in enumerate(cats):
        progress(f"Mercado: categoría {cat}", 0.02 + 0.30 * i / len(cats))
        rows = fetch_category(http, cat, min_mcap)
        log(f"  {cat}: {len(rows)} monedas")
        for r in rows:
            cid = r.get("id")
            if not cid:
                continue
            c = coins.setdefault(cid, {"raw": r, "sectors": set(), "cg_cats": set()})
            c["sectors"].add(sid)
            c["cg_cats"].add(cat)
    excluded = set()
    for i, cat in enumerate(EXCLUDE_CATS):
        progress(f"Exclusiones: {cat}", 0.32 + 0.08 * i / len(EXCLUDE_CATS))
        data = http.get(f"{CG}/coins/markets?vs_currency=usd&category={cat}&order=market_cap_desc"
                        f"&per_page=250&page=1", ttl=6 * 3600)
        for r in data or []:
            excluded.add(r.get("id"))
    return coins, excluded


def fetch_context(http):
    glob = (http.get(f"{CG}/global", ttl=1500) or {}).get("data", {})
    trending = http.get(f"{CG}/search/trending", ttl=1500) or {}
    trend_ids = {c["item"]["id"] for c in trending.get("coins", []) if c.get("item")}
    btc = http.get(f"{CG}/coins/markets?vs_currency=usd&ids=bitcoin,ethereum,solana"
                   f"&price_change_percentage=24h,7d,30d,1y", ttl=1500) or []
    majors = {c["id"]: c for c in btc}
    b = majors.get("bitcoin", {})
    market = {
        "total_mcap": num(glob.get("total_market_cap", {}).get("usd")),
        "mcap_ch24": num(glob.get("market_cap_change_percentage_24h_usd")),
        "btc_dom": num(glob.get("market_cap_percentage", {}).get("btc")),
        "btc_price": num(b.get("current_price")),
        "btc_ch7": num(b.get("price_change_percentage_7d_in_currency")),
        "btc_ch30": num(b.get("price_change_percentage_30d_in_currency")),
        "eth_ch30": num(majors.get("ethereum", {}).get("price_change_percentage_30d_in_currency")),
        "sol_ch30": num(majors.get("solana", {}).get("price_change_percentage_30d_in_currency")),
    }
    return market, trend_ids


def fetch_defillama(http):
    """Devuelve gecko_id -> {tvl, tvl_ch7, fees30, fees_prev30, rev30, rev_prev30, llama_slug, llama_cat}."""
    out: dict[str, dict] = defaultdict(lambda: {"tvl": 0.0, "tvl_prev7": 0.0, "fees30": None,
                                                "fees_prev30": None, "rev30": None, "rev_prev30": None,
                                                "llama_slug": None, "llama_cat": None, "kind": None})
    protocols = http.get(f"{LLAMA}/protocols", ttl=3600) or []
    lite = http.get(f"{LLAMA}/lite/protocols2", ttl=3600) or {}
    id_to_gecko, parent_to_gecko = {}, {}
    for pp in lite.get("parentProtocols", []) if isinstance(lite, dict) else []:
        if pp.get("gecko_id") and pp.get("id"):
            parent_to_gecko[pp["id"]] = pp["gecko_id"]
    for p in protocols:
        gid = p.get("gecko_id")
        if p.get("parentProtocol") and gid:
            parent_to_gecko.setdefault(p["parentProtocol"], gid)
    for p in protocols:
        gid = p.get("gecko_id") or parent_to_gecko.get(p.get("parentProtocol"))
        if not gid:
            continue
        id_to_gecko[str(p.get("id"))] = gid
        if p.get("category") == "CEX":
            continue
        tvl = num(p.get("tvl")) or 0.0
        ch7 = num(p.get("change_7d"))
        d = out[gid]
        d["kind"] = "protocol"
        d["tvl"] += tvl
        d["tvl_prev7"] += tvl / (1 + ch7 / 100) if ch7 is not None and ch7 > -99 else tvl
        if not d["llama_slug"] or tvl > (d.get("_maxtvl") or 0):
            d["llama_slug"] = (p.get("parentProtocol") or "").replace("parent#", "") or p.get("slug")
            d["llama_cat"] = p.get("category")
            d["_maxtvl"] = tvl

    chains = http.get(f"{LLAMA}/v2/chains", ttl=3600) or []
    chain_name_to_gecko = {}
    for c in chains:
        gid = c.get("gecko_id")
        if not gid:
            continue
        chain_name_to_gecko[(c.get("name") or "").lower()] = gid
        d = out[gid]
        if d["kind"] is None:
            d["kind"] = "chain"
            d["tvl"] = num(c.get("tvl")) or 0.0
            d["tvl_prev7"] = d["tvl"]  # sin variación 7d en este endpoint
            d["llama_slug"] = c.get("name")
            d["llama_cat"] = "Chain"
            d["no_tvl_change"] = True

    for dtype, k30, kprev in (("dailyFees", "fees30", "fees_prev30"), ("dailyRevenue", "rev30", "rev_prev30")):
        ov = http.get(f"{LLAMA}/overview/fees?excludeTotalDataChart=true"
                      f"&excludeTotalDataChartBreakdown=true&dataType={dtype}", ttl=3600) or {}
        for p in ov.get("protocols", []):
            if p.get("protocolType") == "chain":
                gid = chain_name_to_gecko.get((p.get("name") or "").lower())
            else:
                gid = id_to_gecko.get(str(p.get("defillamaId")))
            if not gid:
                continue
            v30, vprev = num(p.get("total30d")), num(p.get("total60dto30d"))
            d = out[gid]
            if v30 is not None:
                d[k30] = (d[k30] or 0) + v30
            if vprev is not None:
                d[kprev] = (d[kprev] or 0) + vprev
    for d in out.values():
        d.pop("_maxtvl", None)
    return dict(out)


def fetch_detail(http, cid):
    url = (f"{CG}/coins/{urllib.parse.quote(cid)}?localization=false&tickers=false&market_data=false"
           f"&community_data=false&developer_data=false&sparkline=false")
    return http.get(url, ttl=24 * 3600)


def fetch_security(http, chain_key, address):
    gp, _ = CHAINS[chain_key]
    if gp == "solana":
        data = http.get(f"{GOPLUS}/solana/token_security?contract_addresses={address}", ttl=24 * 3600)
    else:
        data = http.get(f"{GOPLUS}/token_security/{gp}?contract_addresses={address.lower()}", ttl=24 * 3600)
    if not data or not isinstance(data.get("result"), dict) or not data["result"]:
        return None
    res = data["result"]
    return res.get(address) or res.get(address.lower()) or next(iter(res.values()))


def fetch_honeypot(http, chain_key, address):
    gp, _ = CHAINS[chain_key]
    if gp not in HONEYPOT_CHAINS:
        return None
    return http.get(f"{HONEYPOT}/IsHoneypot?address={address}&chainID={gp}", ttl=24 * 3600)


def fetch_rugcheck(http, mint):
    return http.get(f"{RUGCHECK}/tokens/{mint}/report/summary", ttl=24 * 3600)


def fetch_dex_batch(http, dex_chain, addresses):
    out = {}
    for i in range(0, len(addresses), 30):
        chunk = addresses[i:i + 30]
        data = http.get(f"{DEXS}/tokens/v1/{dex_chain}/{','.join(chunk)}", ttl=900) or []
        for pair in data if isinstance(data, list) else []:
            addr = ((pair.get("baseToken") or {}).get("address") or "")
            out.setdefault(addr.lower(), []).append(pair)
    return out


# ---------------------------------------------------------------------------
# 2. Métricas por moneda
# ---------------------------------------------------------------------------

def bucket_for(mcap):
    for b in BUCKETS:
        if b["min"] <= mcap < b["max"]:
            return b
    return None


def build_records(coins, excluded, llama, trend_ids):
    stats = Counter()
    recs = []
    for cid, c in coins.items():
        r = c["raw"]
        stats["universo"] += 1
        mc = num(r.get("market_cap")) or 0
        b = bucket_for(mc)
        if not b:
            stats["fuera_de_rango"] += 1
            continue
        name = r.get("name") or cid
        if cid in excluded or EXCLUDE_NAME.search(name):
            stats["excluidas_no_proyecto"] += 1
            continue
        vol = num(r.get("total_volume")) or 0
        if vol < b["min_vol"]:
            stats["excluidas_liquidez"] += 1
            continue
        spark = (r.get("sparkline_in_7d") or {}).get("price") or []
        ts = trend_stats(spark)
        ch30 = num(r.get("price_change_percentage_30d_in_currency"))
        ch7 = num(r.get("price_change_percentage_7d_in_currency"))
        if ts is None or ch30 is None or ch7 is None:
            stats["excluidas_sin_datos"] += 1
            continue
        if abs(ch30) < 3 and abs(ch7) < 1.5 and ts["cv"] < 0.006:
            stats["excluidas_no_proyecto"] += 1  # activo con paridad fija
            continue
        sector = min(c["sectors"], key=lambda s: SECTOR_INDEX[s])
        fdv = num(r.get("fully_diluted_valuation"))
        circ = num(r.get("circulating_supply"))
        supply_cap = num(r.get("max_supply")) or num(r.get("total_supply"))
        ll = llama.get(cid) or {}
        tvl = ll.get("tvl") or None
        tvl = tvl if tvl and tvl > 1e6 else None
        tvl_ch7 = None
        if tvl and not ll.get("no_tvl_change") and ll.get("tvl_prev7"):
            tvl_ch7 = (ll["tvl"] / ll["tvl_prev7"] - 1) * 100
        fees30, rev30 = ll.get("fees30"), ll.get("rev30")
        fees_growth = None
        if fees30 and ll.get("fees_prev30") and ll["fees_prev30"] > 1e4:
            fees_growth = (fees30 / ll["fees_prev30"] - 1) * 100
        rev_growth = None
        if rev30 and ll.get("rev_prev30") and ll["rev_prev30"] > 1e4:
            rev_growth = (rev30 / ll["rev_prev30"] - 1) * 100
        annual = 365 / 30
        rec = {
            "id": cid, "symbol": (r.get("symbol") or "").upper(), "name": name,
            "image": r.get("image"), "rank": r.get("market_cap_rank"),
            "sector": sector, "sectors": sorted(c["sectors"], key=lambda s: SECTOR_INDEX[s]),
            "bucket": b["id"], "price": num(r.get("current_price")), "mcap": mc, "fdv": fdv,
            "volume": vol, "turnover": vol / mc if mc else None,
            "ch24": num(r.get("price_change_percentage_24h_in_currency")), "ch7": ch7, "ch30": ch30,
            "ch1y": num(r.get("price_change_percentage_1y_in_currency")),
            "ath": num(r.get("ath")), "ath_dd": num(r.get("ath_change_percentage")),
            "ath_date": r.get("ath_date"), "atl_up": num(r.get("atl_change_percentage")),
            "fdv_ratio": (fdv / mc) if fdv and mc else None,
            "circ_ratio": min(1.0, circ / supply_cap) if circ and supply_cap else None,
            "trend": ts, "spark": downsample(spark),
            "tvl": tvl, "tvl_ch7": tvl_ch7, "llama_slug": ll.get("llama_slug"),
            "llama_cat": ll.get("llama_cat"), "llama_kind": ll.get("kind"),
            "fees30": fees30 if fees30 and fees30 > 0 else None, "fees_growth": fees_growth,
            "rev30": rev30 if rev30 and rev30 > 0 else None, "rev_growth": rev_growth,
            "mcap_tvl": (mc / tvl) if tvl else None,
            "tvl_skewed": bool(tvl) and ll.get("llama_cat") in TVL_SKEW_CATS,
            "pf": (mc / (fees30 * annual)) if fees30 and fees30 > 1e4 else None,
            "ps": (mc / (rev30 * annual)) if rev30 and rev30 > 1e4 else None,
            "rev_yield": (rev30 * annual / mc * 100) if rev30 and rev30 > 1e4 else None,
            "trending": cid in trend_ids,
        }
        recs.append(rec)
        stats["elegibles"] += 1
    return recs, stats


def score_market(recs, market):
    """Puntuaciones que solo dependen de datos de mercado y DefiLlama (todo el universo)."""
    R = {k: Ranker([r[k] for r in recs]) for k in ("ch7", "ch30", "ch24", "tvl_ch7", "fees_growth", "rev_yield")}
    def mtvl_ok(r):
        return r["mcap_tvl"] and not r["tvl_skewed"]
    R_mtvl = {k: Ranker([math.log(r["mcap_tvl"]) for r in recs if mtvl_ok(r) and (r["llama_kind"] == "chain") == (k == "chain")])
              for k in ("chain", "protocol")}
    R_pf = Ranker([math.log(r["pf"]) for r in recs if r["pf"]])
    R_ps = Ranker([math.log(r["ps"]) for r in recs if r["ps"]])

    # medianas por sector y por sector+tramo
    by_sector = defaultdict(list)
    by_sb = defaultdict(list)
    for r in recs:
        by_sector[r["sector"]].append(r)
        by_sb[(r["sector"], r["bucket"])].append(r)
    sector_stats = {}
    for s, rs in by_sector.items():
        mt = [x["mcap_tvl"] for x in rs if x["mcap_tvl"] and not x["tvl_skewed"]]
        sector_stats[s] = {
            "n": len(rs),
            "ch30_med": statistics.median([x["ch30"] for x in rs]),
            "ch7_med": statistics.median([x["ch7"] for x in rs]),
            "turnover_med": statistics.median([x["turnover"] for x in rs]),
            "mcap_tvl_med": statistics.median(mt) if len(mt) >= 3 else None,
        }
    sb_turn = {k: statistics.median([x["turnover"] for x in v]) for k, v in by_sb.items()}
    btc30 = market.get("btc_ch30") or 0

    for r in recs:
        ts = r["trend"]
        tq = 50 + 50 * ts["r2"] * (1 if ts["slope7"] > 0 else -1)
        mom = 0.45 * R["ch30"](r["ch30"]) + 0.30 * R["ch7"](r["ch7"]) + 0.25 * tq
        overheated = (r["ch24"] or 0) > 30 or r["ch7"] > 100 or r["ch30"] > 250
        if overheated:
            mom = min(mom, 70)
        r["overheated"] = overheated

        v_parts = []
        if mtvl_ok(r):
            kind = "chain" if r["llama_kind"] == "chain" else "protocol"
            v_parts.append(100 - R_mtvl[kind](math.log(r["mcap_tvl"])) + (10 if r["mcap_tvl"] < 1 else 0))
        if r["pf"]:
            v_parts.append(100 - R_pf(math.log(r["pf"])))
        if r["ps"]:
            v_parts.append(100 - R_ps(math.log(r["ps"])))
        valor = clamp(mean_present(v_parts)) if v_parts else None

        f_parts = [R["tvl_ch7"](r["tvl_ch7"]), R["fees_growth"](r["fees_growth"])]
        if r["rev_yield"]:
            f_parts.append(R["rev_yield"](r["rev_yield"]))
        fund = mean_present(f_parts)

        liq = liquidity_score(r["turnover"])
        tok = tokenomics_score(r["fdv_ratio"], r["circ_ratio"])
        ss = sector_stats[r["sector"]]
        r["rel30"] = r["ch30"] - ss["ch30_med"]
        r["vs_btc30"] = r["ch30"] - btc30
        r["turn_rel"] = r["turnover"] / sb_turn[(r["sector"], r["bucket"])] if sb_turn.get((r["sector"], r["bucket"])) else None
        r["trend_q"] = tq
        r["scores"] = {"momentum": mom, "valor": valor, "fundamentales": fund, "liquidez": liq,
                       "tokenomics": tok, "atencion": None, "seguridad": None}
        r["pre"] = composite(r["scores"])[0]
    R_rel = Ranker([r["rel30"] for r in recs])
    R_turnrel = Ranker([r["turn_rel"] for r in recs])
    for r in recs:
        r["_rel_pr"] = R_rel(r["rel30"])
        r["_turnrel_pr"] = R_turnrel(r["turn_rel"])
        r["_R"] = None
    return sector_stats, R


# Valor que se imputa a una señal sin datos: la falta de evidencia no suma puntos.
MISSING = {"seguridad": 65.0}
MISSING_DEFAULT = 45.0


def composite(scores):
    total = sum(WEIGHTS.values())
    val = sum(WEIGHTS[k] * (v if v is not None else MISSING.get(k, MISSING_DEFAULT))
              for k, v in scores.items()) / total
    coverage = sum(WEIGHTS[k] for k, v in scores.items() if v is not None) / total
    return val, coverage


def archetype_scores(r, R):
    s = r["scores"]
    out = {}
    ts = r["trend"]
    if r["ch30"] > 10 and r["ch7"] > 0 and not r["overheated"]:
        out["tendencia"] = 0.45 * R["ch30"](r["ch30"]) + 0.25 * R["ch7"](r["ch7"]) + 30 * ts["r2"]
    if s["valor"] is not None and ((r["mcap_tvl"] and not r["tvl_skewed"] and r["mcap_tvl"] < 1.5) or (r["pf"] and r["pf"] < 40)
                                   or (r["ps"] and r["ps"] < 25)):
        out["infravalorado"] = s["valor"]
    if r["ath_dd"] is not None and r["ath_dd"] <= -75 and r["ch7"] > 3 and r["ch30"] > -5:
        depth = clamp(40 + (-r["ath_dd"] - 75) / 22 * 60)
        out["rebote"] = 0.35 * depth + 0.4 * R["ch7"](r["ch7"]) + 0.25 * R["ch30"](r["ch30"])
    if r["turn_rel"] and r["turn_rel"] >= 1.6 and abs(r["ch7"]) <= 12 and r["turnover"] < 1.2:
        bp = r.get("buy_ratio")
        if bp is None or bp >= 1.0:
            flat = clamp(100 - abs(r["ch7"]) * 6)
            bpart = clamp(50 + (bp - 1) * 250) if bp else 50
            out["acumulacion"] = 0.6 * r["_turnrel_pr"] + 0.2 * flat + 0.2 * bpart
    if (r["tvl_ch7"] is not None and r["tvl_ch7"] > 5) or (r["fees_growth"] is not None and r["fees_growth"] > 20):
        out["crecimiento"] = s["fundamentales"] if s["fundamentales"] is not None else 50
    if r["rev_yield"] is not None and r["rev_yield"] > 2:
        out["ingresos"] = R["rev_yield"](r["rev_yield"])
    if r["rel30"] > 15 and r["vs_btc30"] > 10 and not r["overheated"]:
        out["fuerza"] = r["_rel_pr"]
    # Atención *emergente*: en tendencia hoy, o muchos seguidores para su tamaño pero con el precio
    # acompañando (si no, suele ser atención heredada de cuando el proyecto valía mucho más).
    if s["atencion"] is not None and r["ch7"] > -5 and (
            r["trending"] or ((r.get("_watch_pr") or 0) >= 75 and r["ch7"] > 0 and r["ch30"] > -10)):
        out["atencion"] = s["atencion"]
    base = r.get("final", r["pre"])
    if (r["fdv_ratio"] is not None and r["fdv_ratio"] <= 1.05 and (r["circ_ratio"] or 0) >= 0.9
            and base >= 55 and (r["rel30"] > 0 or (s["valor"] or 0) >= 60)):
        out["tokenomics"] = 0.3 * (s["tokenomics"] or 0) + 0.7 * base
    return {k: clamp(v) for k, v in out.items()}


# ---------------------------------------------------------------------------
# 3. Seguridad del contrato (GoPlus) y liquidez on-chain (DexScreener)
# ---------------------------------------------------------------------------

def flag(v):
    return str(v) == "1"


def holder_concentration(holders, key_pct="percent"):
    tot = 0.0
    for h in (holders or [])[:10]:
        if h.get("is_locked") in (1, "1") or h.get("tag") or h.get("is_contract") in (1, "1"):
            continue
        tot += num(h.get(key_pct)) or 0
    return tot  # fracción 0-1


def assess_evm(sec):
    checks, score, critical = [], 100.0, False

    def chk(label, bad, penalty, crit=False, detail=None):
        nonlocal score, critical
        sev = "alto" if crit or penalty >= 25 else ("medio" if penalty >= 10 else "bajo")
        checks.append({"label": label, "ok": not bad, "detail": detail, "sev": sev})
        if bad:
            score -= penalty
            critical = critical or crit

    buy_tax = num(sec.get("buy_tax")) or 0
    sell_tax = num(sec.get("sell_tax")) or 0
    owner = (sec.get("owner_address") or "").lower()
    renounced = owner in ("", "0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead")
    chk("No es honeypot (se puede vender)", flag(sec.get("is_honeypot")) or flag(sec.get("cannot_sell_all")), 100, True)
    chk("Código verificado y público", sec.get("is_open_source") == "0", 35, True)
    chk("El propietario no puede alterar saldos", flag(sec.get("owner_change_balance")), 45, True)
    chk("Sin propietario oculto", flag(sec.get("hidden_owner")), 30)
    chk("No se puede recuperar la propiedad", flag(sec.get("can_take_back_ownership")), 25)
    chk("Sin autodestrucción", flag(sec.get("selfdestruct")), 25)
    tax = max(buy_tax, sell_tax)
    chk("Tasas de compra/venta ≤ 3 %", tax > 0.03, 40 if tax > 0.1 else 15, tax > 0.1,
        f"compra {buy_tax * 100:.1f} % · venta {sell_tax * 100:.1f} %")
    chk("Las tasas no se pueden modificar", flag(sec.get("slippage_modifiable")), 15)
    chk("Sin acuñación libre del propietario", flag(sec.get("is_mintable")) and not renounced, 10)
    chk("Contrato no actualizable (no proxy)", flag(sec.get("is_proxy")), 8)
    chk("Transferencias no pausables", flag(sec.get("transfer_pausable")), 6)
    chk("Sin lista negra de direcciones", flag(sec.get("is_blacklisted")), 6)
    chk("Sin enfriamiento de trading", flag(sec.get("trading_cooldown")), 5)
    conc = holder_concentration(sec.get("holders"))
    chk("Top 10 carteras sin etiquetar < 30 %", conc > 0.30, 15 if conc > 0.5 else 7, False,
        f"{conc * 100:.0f} % del suministro")
    creator = num(sec.get("creator_percent")) or 0
    chk("El creador tiene < 10 %", creator > 0.10, 10, False, f"{creator * 100:.1f} %")
    cex = (sec.get("is_in_cex") or {})
    lp_locked = sum(num(h.get("percent")) or 0 for h in (sec.get("lp_holders") or [])
                    if h.get("is_locked") in (1, "1") or str(h.get("address", "")).lower() in
                    ("0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead"))
    extra = {
        "lp_locked": min(1.0, lp_locked) if sec.get("lp_holders") else None,
        "holders": int(num(sec.get("holder_count")) or 0) or None,
        "cex": cex.get("cex_list") if isinstance(cex, dict) and flag(cex.get("listed")) else None,
        "owner_renounced": renounced, "top10": conc,
        "buy_tax": buy_tax, "sell_tax": sell_tax,
    }
    return clamp(score), critical, checks, extra


def assess_solana(sec):
    checks, score, critical = [], 100.0, False

    def status(k):
        v = sec.get(k)
        return flag(v.get("status")) if isinstance(v, dict) else flag(v)

    def chk(label, bad, penalty, crit=False, detail=None):
        nonlocal score, critical
        sev = "alto" if crit or penalty >= 25 else ("medio" if penalty >= 10 else "bajo")
        checks.append({"label": label, "ok": not bad, "detail": detail, "sev": sev})
        if bad:
            score -= penalty
            critical = critical or crit

    chk("Nadie puede alterar saldos", status("balance_mutable_authority"), 45, True)
    chk("Token transferible", flag(sec.get("non_transferable")), 100, True)
    chk("Sin autoridad de congelación", status("freezable"), 15)
    chk("Cuentas no cerrables por terceros", status("closable"), 20)
    chk("Sin autoridad de acuñación", status("mintable"), 12)
    tf = sec.get("transfer_fee") or {}
    has_fee = bool(tf) and (num(tf.get("fee_rate")) or 0) > 0 if isinstance(tf, dict) else False
    chk("Sin comisión por transferencia", has_fee, 15)
    chk("Comisión no modificable", status("transfer_fee_upgradable"), 10)
    chk("Sin hooks de transferencia", bool(sec.get("transfer_hook")), 10)
    conc = holder_concentration(sec.get("holders"))
    chk("Top 10 carteras sin etiquetar < 30 %", conc > 0.30, 15 if conc > 0.5 else 7, False,
        f"{conc * 100:.0f} % del suministro")
    if flag(sec.get("trusted_token")):
        score = min(100, score + 10)
    extra = {"holders": int(num(sec.get("holder_count")) or 0) or None, "cex": None,
             "owner_renounced": None, "top10": conc, "trusted": flag(sec.get("trusted_token"))}
    return clamp(score), critical, checks, extra


HONEYPOT_RISK = {"very_low": 100, "low": 92, "medium": 70, "high": 40, "very_high": 15, "honeypot": 0}
RUGCHECK_ES = {
    "Mint Authority still enabled": "Autoridad de acuñación activa",
    "Freeze Authority still enabled": "Autoridad de congelación activa",
    "Mutable metadata": "Metadatos modificables",
    "Low Liquidity": "Liquidez baja",
    "Low amount of LP Providers": "Pocos proveedores de liquidez",
    "Large Amount of LP Unlocked": "Gran parte de la liquidez sin bloquear",
    "Top 10 holders high ownership": "Mucha concentración en el top 10",
    "Single holder ownership": "Un solo holder concentra mucho",
    "High ownership": "Alta concentración de propiedad",
    "Copycat token": "Posible token imitación",
    "High holder correlation": "Holders sospechosamente correlacionados",
}


def goplus_source(chain_key, address, score, critical, checks):
    gp, _ = CHAINS[chain_key]
    return {"name": "GoPlus", "what": "Banderas del contrato", "score": score, "critical": critical,
            "notes": [c["label"] for c in checks if not c["ok"]],
            "url": f"https://gopluslabs.io/token-security/{gp}/{address}"}


def assess_honeypot(d, chain_key, address):
    gp, _ = CHAINS[chain_key]
    s = d.get("summary") or {}
    risk = str(s.get("risk") or "unknown").lower()
    is_hp = bool((d.get("honeypotResult") or {}).get("isHoneypot"))
    sim = d.get("simulationResult") or {}
    bt, st = num(sim.get("buyTax")), num(sim.get("sellTax"))
    notes, critical = [], False
    if d.get("simulationSuccess") and bt is not None and st is not None:
        notes.append(f"Compra y venta simuladas: impuesto {es_num(bt, 1)} % al comprar, {es_num(st, 1)} % al vender")
    for f in (s.get("flags") or d.get("flags") or [])[:4]:
        txt = f.get("description") or f.get("flag") if isinstance(f, dict) else str(f)
        if txt:
            notes.append(str(txt))
    score = HONEYPOT_RISK.get(risk)
    if is_hp or risk == "honeypot":
        critical, score = True, 0
        notes.insert(0, "La simulación no pudo vender: honeypot")
    if st is not None and st > 10:
        critical = True
        score = min(score if score is not None else 100, 30)
    if not d.get("simulationSuccess") and not is_hp:
        score = None
        notes.insert(0, "No se pudo simular la compra y venta (sin pool compatible)")
    return {"name": "Honeypot.is", "what": "Simulación de compra y venta", "score": score, "critical": critical,
            "notes": notes, "url": f"https://honeypot.is/{HONEYPOT_CHAINS[gp]}?address={address}"}


def assess_rugcheck(d, mint):
    risks_ = d.get("risks") or []
    danger = [x for x in risks_ if x.get("level") == "danger"]
    warn = [x for x in risks_ if x.get("level") == "warn"]
    score = clamp(100 - 20 * len(danger) - 6 * len(warn))
    critical = bool(d.get("rugged")) or any(re.search(r"rug|honeypot", x.get("name", ""), re.I) for x in danger)
    notes = [("Grave: " if x in danger else "") + RUGCHECK_ES.get(x.get("name"), x.get("name", "")) for x in danger + warn]
    lp = num(d.get("lpLockedPct"))
    if lp is not None:
        notes.append(f"Liquidez bloqueada: {es_num(lp * 100 if lp <= 1 else lp, 0)} %")
    return {"name": "RugCheck", "what": "Riesgos del token en Solana", "score": score, "critical": critical,
            "notes": notes, "url": f"https://rugcheck.xyz/tokens/{mint}",
            "lp_locked": (lp if lp <= 1 else lp / 100) if lp is not None else None}


def combine_security(sources, checks, extra):
    """Consenso entre auditores automáticos. Un fallo crítico en cualquiera descarta la moneda."""
    scored = [x for x in sources if x["score"] is not None]
    if not scored:
        return {"level": "sin_datos", "score": 60, "critical": False, "checks": checks, "sources": sources,
                "consensus": None, "disagree": False, **extra}
    gp = next((x for x in scored if x["name"] == "GoPlus"), None)
    others = [x for x in scored if x is not gp]
    if gp and others:
        score = 0.6 * gp["score"] + 0.4 * sum(x["score"] for x in others) / len(others)
    else:
        score = scored[0]["score"] if len(scored) == 1 else sum(x["score"] for x in scored) / len(scored)
    critical = any(x["critical"] for x in sources)
    spread = max(x["score"] for x in scored) - min(x["score"] for x in scored)
    disagree = len(scored) > 1 and spread > 35
    ok = sum(1 for x in scored if not x["critical"] and x["score"] >= 75)
    # «Limpio» exige que todos los auditores con opinión lo vean limpio.
    level = "riesgo" if critical or score < 50 else (
        "precaucion" if score < 75 or disagree or ok < len(scored) else "limpio")
    return {"level": level, "score": clamp(score), "critical": critical, "checks": checks, "sources": sources,
            "consensus": f"{ok}/{len(scored)}", "disagree": disagree, **extra}


def pick_contract(detail):
    platforms = {k: v for k, v in (detail.get("platforms") or {}).items() if k and v}
    home = detail.get("asset_platform_id")
    if not home:
        return None, None, True  # activo nativo de su propia cadena
    if home in CHAINS and platforms.get(home):
        return home, platforms[home], False
    for ch in CHAIN_PRIORITY:
        if platforms.get(ch):
            return ch, platforms[ch], False
    return None, None, False


def summarize_dex(pairs, address):
    pairs = [p for p in pairs if ((p.get("baseToken") or {}).get("address") or "").lower() == address.lower()]
    if not pairs:
        return None
    liq = sum(num((p.get("liquidity") or {}).get("usd")) or 0 for p in pairs)
    vol = sum(num((p.get("volume") or {}).get("h24")) or 0 for p in pairs)
    buys = sum(((p.get("txns") or {}).get("h24") or {}).get("buys", 0) for p in pairs)
    sells = sum(((p.get("txns") or {}).get("h24") or {}).get("sells", 0) for p in pairs)
    created = [p.get("pairCreatedAt") for p in pairs if p.get("pairCreatedAt")]
    top = max(pairs, key=lambda p: num((p.get("liquidity") or {}).get("usd")) or 0)
    return {"liquidity": liq, "volume24": vol, "buys24": buys, "sells24": sells,
            "buy_ratio": (buys / sells) if sells else None, "pools": len(pairs),
            "oldest_pool": min(created) if created else None,
            "url": top.get("url"), "dex": top.get("dexId"), "chain": top.get("chainId")}


# ---------------------------------------------------------------------------
# 4. Explicaciones en lenguaje natural
# ---------------------------------------------------------------------------

def evidence(r, sector_stats, market):
    """Lista de (fuerza, arquetipo, texto) a favor."""
    out = []
    ss = sector_stats[r["sector"]]
    sl = SECTOR_LABEL[r["sector"]]
    ts = r["trend"]
    if r["ch30"] > 10:
        out.append((r["scores"]["momentum"], "tendencia",
                    f"{fmt_pct(r['ch30'])} en 30 días y {fmt_pct(r['ch7'])} en 7, con una tendencia "
                    f"{'limpia' if ts['r2'] > 0.6 else 'irregular'} (R² {es_num(ts['r2'], 2)} en la última semana)."))
    if r["mcap_tvl"] and not r["tvl_skewed"]:
        med = ss.get("mcap_tvl_med")
        cmp_txt = f", frente a una mediana de {fmt_x(med)} en {sl}" if med else ""
        out.append((100 - min(100, r["mcap_tvl"] * 40), "infravalorado",
                    f"Cotiza a {fmt_x(r['mcap_tvl'])} su TVL ({fmt_usd(r['tvl'])}){cmp_txt}."))
    if r["pf"]:
        out.append((clamp(100 - r["pf"] * 1.5), "infravalorado",
                    f"Comisiones de {fmt_usd(r['fees30'])} en 30 días: ratio precio/comisiones de {fmt_x(r['pf'])}."))
    if r["rev_yield"]:
        out.append((clamp(r["rev_yield"] * 6), "ingresos",
                    f"Ingresos anualizados de {fmt_usd(r['rev30'] * 365 / 30)}: un {es_num(r['rev_yield'], 1)} % "
                    f"de su capitalización al año."))
    if r["tvl_ch7"] is not None and r["tvl_ch7"] > 5:
        out.append((clamp(50 + r["tvl_ch7"] * 2), "crecimiento",
                    f"El TVL creció {fmt_pct(r['tvl_ch7'])} en 7 días."))
    if r["fees_growth"] is not None and r["fees_growth"] > 20:
        out.append((clamp(50 + r["fees_growth"] / 2), "crecimiento",
                    f"Comisiones del último mes {fmt_pct(r['fees_growth'])} frente al mes anterior."))
    if r["ath_dd"] is not None and r["ath_dd"] <= -75 and r["ch7"] > 3:
        out.append((clamp(-r["ath_dd"]), "rebote",
                    f"Está {es_num(-r['ath_dd'], 0)} % por debajo de su máximo ({fmt_date(r['ath_date'])}) "
                    f"y gira al alza: {fmt_pct(r['ch7'])} en 7 días."))
    if r["turn_rel"] and r["turn_rel"] >= 1.6:
        out.append((clamp(r["_turnrel_pr"]), "acumulacion",
                    f"Mueve cada día el {es_num(r['turnover'] * 100, 0)} % de su capitalización, "
                    f"{fmt_x(r['turn_rel'])} lo normal en {sl} de su tamaño, con el precio a {fmt_pct(r['ch7'])} en 7 días."))
    if r["rel30"] > 15:
        out.append((clamp(r["_rel_pr"]), "fuerza",
                    f"Supera a la mediana de {sl} por {es_num(r['rel30'], 0)} puntos en 30 días "
                    f"y a bitcoin por {es_num(r['vs_btc30'], 0)}."))
    if r.get("watchlist"):
        out.append((clamp(r.get("_watch_pr") or 0), "atencion",
                    f"{es_num(r['watchlist'], 0)} usuarios lo siguen en CoinGecko: "
                    f"{fmt_x(r['watch_rel'])} la atención media por dólar de capitalización."))
    if r["trending"]:
        out.append((90, "atencion", "Aparece hoy entre las búsquedas en tendencia de CoinGecko."))
    if r["fdv_ratio"] is not None and r["fdv_ratio"] <= 1.05 and (r["circ_ratio"] or 0) >= 0.9:
        out.append((80, "tokenomics",
                    f"El {es_num((r['circ_ratio'] or 1) * 100, 0)} % del suministro ya circula: "
                    f"FDV ≈ capitalización, sin desbloqueos que diluyan."))
    dex = r.get("dex")
    if dex and dex.get("buy_ratio") and dex["buy_ratio"] > 1.15 and dex["buys24"] + dex["sells24"] > 200:
        out.append((clamp(50 + (dex["buy_ratio"] - 1) * 150), "acumulacion",
                    f"En DEX hubo {es_num(dex['buy_ratio'], 2)} compras por cada venta en 24 h."))
    sec = r.get("security") or {}
    if sec.get("level") == "limpio":
        names = " y ".join(x["name"] for x in sec.get("sources", []) if x["score"] is not None)
        out.append((60, None, f"Contrato sin alertas graves en {sec.get('consensus')} auditorías automáticas ({names})."))
    return out


def risks(r):
    out = []
    if r["overheated"]:
        out.append(("alto", f"Sobrecalentado: {fmt_pct(r['ch24'])} en 24 h y {fmt_pct(r['ch7'])} en 7 días. "
                            "Riesgo de entrar tarde."))
    if r["fdv_ratio"] and r["fdv_ratio"] > 2:
        out.append(("alto" if r["fdv_ratio"] > 4 else "medio",
                    f"Dilución pendiente: la FDV es {fmt_x(r['fdv_ratio'])} la capitalización "
                    f"(solo circula el {es_num((r['circ_ratio'] or 0) * 100, 0)} %)."))
    if r["turnover"] and r["turnover"] > 1.0:
        out.append(("medio", f"Volumen diario del {es_num(r['turnover'] * 100, 0)} % de la capitalización: "
                             "posible trading de lavado o especulación extrema."))
    if r["ch1y"] is not None and r["ch1y"] < -75:
        out.append(("medio", f"Tendencia anual muy bajista: {fmt_pct(r['ch1y'])} en 12 meses."))
    if r["trend"]["vol_daily"] and r["trend"]["vol_daily"] > 0.09:
        out.append(("medio", f"Volatilidad alta: oscilación diaria típica del {es_num(r['trend']['vol_daily'] * 100, 0)} %."))
    if r["trend"]["mdd7"] < -0.25:
        out.append(("medio", f"Caída máxima del {es_num(-r['trend']['mdd7'] * 100, 0)} % dentro de la última semana."))
    dex = r.get("dex")
    if dex and dex["liquidity"] < 250e3 and not (r.get("security") or {}).get("cex"):
        out.append(("alto" if dex["liquidity"] < 100e3 else "medio",
                    f"Liquidez on-chain escasa: {fmt_usd(dex['liquidity'])} en pools DEX."))
    if dex and dex.get("oldest_pool"):
        age_days = (time.time() * 1000 - dex["oldest_pool"]) / 86400000
        if age_days < 120:
            out.append(("medio", f"Token joven: su primer pool tiene {int(age_days)} días."))
    sec = r.get("security") or {}
    for c in sec.get("checks", []):
        if not c["ok"]:
            out.append((c.get("sev", "bajo"),
                        f"Contrato: falla «{c['label']}»" + (f" ({c['detail']})" if c.get("detail") else "") + "."))
    for src in sec.get("sources", []):
        if src["name"] != "GoPlus" and src["score"] is not None and src["score"] < 75:
            out.append(("alto" if src["critical"] else "medio",
                        f"{src['name']}: " + "; ".join(n for n in src["notes"][:3]) + "."))
    if sec.get("disagree"):
        vals = ", ".join(f"{x['name']} {int(x['score'])}" for x in sec["sources"] if x["score"] is not None)
        out.append(("medio", f"Los auditores discrepan ({vals}): revisa el contrato a mano."))
    if sec.get("level") == "sin_datos":
        out.append(("bajo", "Contrato en una cadena que el escáner no audita: revísalo a mano."))
    if r["scores"]["valor"] is None and r["sector"] not in ("meme",):
        out.append(("bajo", "Sin datos de TVL ni ingresos: la valoración se apoya solo en el mercado."))
    if r["sector"] == "meme":
        out.append(("medio", "Memecoin: sin flujos de caja, depende por completo del sentimiento."))
    order = {"alto": 0, "medio": 1, "bajo": 2}
    return sorted(out, key=lambda x: order[x[0]])


SECTOR_LABEL = {s["id"]: s["label"] for s in SECTORS}
BUCKET_LABEL = {b["id"]: b["label"] for b in BUCKETS}


# ---------------------------------------------------------------------------
# 5. Selección de las 16
# ---------------------------------------------------------------------------

def shortlist(recs, R, per_sector_bucket=1, per_arch_bucket=3):
    chosen = {}
    by_sb = defaultdict(list)
    for r in recs:
        by_sb[(r["sector"], r["bucket"])].append(r)
    for rs in by_sb.values():
        for r in sorted(rs, key=lambda x: -x["pre"])[:per_sector_bucket]:
            chosen[r["id"]] = r
    for b in BUCKETS:
        rs = [r for r in recs if r["bucket"] == b["id"]]
        arch = defaultdict(list)
        for r in rs:
            for k, v in archetype_scores(r, R).items():
                arch[k].append((v, r))
        for k, lst in arch.items():
            for v, r in sorted(lst, key=lambda x: -x[0])[:per_arch_bucket]:
                chosen[r["id"]] = r
    return list(chosen.values())


def select(cands):
    picks = []
    used_bucket = Counter()
    used_sector = Counter()
    used_arch = Counter()
    quota = {b["id"]: b["quota"] for b in BUCKETS}
    taken = set()

    def ok(c, a, sector_cap, arch_cap=MAX_PER_ARCHETYPE):
        return (c["id"] not in taken and used_bucket[c["bucket"]] < quota[c["bucket"]]
                and used_sector[c["sector"]] < sector_cap and used_arch[a] < arch_cap)

    def take(c, a):
        c["archetype"] = a
        c["pick_score"] = 0.5 * c["final"] + 0.5 * c["arch"][a]
        picks.append(c)
        taken.add(c["id"])
        used_bucket[c["bucket"]] += 1
        used_sector[c["sector"]] += 1
        used_arch[a] += 1

    def ps(c, a):
        return 0.5 * c["final"] + 0.5 * c["arch"][a]

    # Fase 1: un representante por motivo, empezando por los motivos más escasos.
    counts = Counter(a for c in cands for a in c["arch"])
    for a in sorted(counts, key=lambda k: counts[k]):
        opts = [c for c in cands if a in c["arch"] and ok(c, a, MAX_PER_SECTOR)]
        if opts:
            best = max(opts, key=lambda c: ps(c, a))
            if ps(best, a) >= 55:
                take(best, a)
    # Fase 2: rellenar por puntuación; si un tramo se queda corto se relajan, por este orden,
    # la nota mínima, el tope por motivo y el tope por sector.
    for min_ps, arch_cap, sector_cap in ((55, MAX_PER_ARCHETYPE, MAX_PER_SECTOR), (0, MAX_PER_ARCHETYPE, MAX_PER_SECTOR),
                                         (0, MAX_PER_ARCHETYPE + 1, MAX_PER_SECTOR), (0, 99, MAX_PER_SECTOR + 1), (0, 99, 99)):
        pairs = sorted(((ps(c, a), c, a) for c in cands for a in c["arch"]), key=lambda x: -x[0])
        for v, c, a in pairs:
            if len(picks) >= TOTAL_PICKS:
                break
            if v >= min_ps and ok(c, a, sector_cap, arch_cap):
                take(c, a)
        if len(picks) >= TOTAL_PICKS:
            break
    # Fase 3: si algún tramo no tiene suficientes candidatos con motivo, completar por nota.
    if len(picks) < TOTAL_PICKS:
        for c in sorted(cands, key=lambda c: -c["final"]):
            if len(picks) >= TOTAL_PICKS:
                break
            if c["id"] in taken or used_bucket[c["bucket"]] >= quota[c["bucket"]]:
                continue
            c["arch"].setdefault("tendencia" if c["ch30"] > 0 else "tokenomics", c["final"])
            a = max(c["arch"], key=lambda k: c["arch"][k])
            take(c, a)
    order = {b["id"]: i for i, b in enumerate(BUCKETS)}
    picks.sort(key=lambda c: (order[c["bucket"]], -c["pick_score"]))
    return picks


# ---------------------------------------------------------------------------
# Zona shitcoin: micro-caps de alto riesgo con filtros muy estrictos
# ---------------------------------------------------------------------------

GEM_RANGE = (1e6, 15e6)
GEM_PICKS = 4
GEM_RULES = {"min_vol": 150e3, "min_liq": 75e3, "min_liq_ratio": 0.03, "min_age_days": 10,
             "min_txns": 250, "max_top10": 0.35, "max_tax": 0.01, "min_lp_locked": 0.3,
             "max_ch7": 150, "max_ch24": 60, "audit": 30}
GEM_REASONS = [
    {"id": "traccion", "label": "Tracción orgánica",
     "desc": "Muchas operaciones y volumen alto para su liquidez, con más compras que ventas."},
    {"id": "despegue", "label": "Despegue temprano",
     "desc": "Token joven que ya superó sus primeras semanas, con el volumen acelerando y el precio subiendo."},
    {"id": "superviviente", "label": "Superviviente en ascenso",
     "desc": "Lleva meses cotizando, ha aguantado el mercado bajista y ahora gira al alza."},
    {"id": "solidez", "label": "Base sólida",
     "desc": "Liquidez profunda, contrato impecable y holders repartidos: la micro-cap más sana de su clase."},
]


def fetch_platforms(http):
    data = http.get(f"{CG}/coins/list?include_platform=true", ttl=24 * 3600) or []
    return {c["id"]: {k: v for k, v in (c.get("platforms") or {}).items() if k and v}
            for c in data if isinstance(c, dict) and c.get("id")}


def audit_contract(http, ch, addr):
    gp = fetch_security(http, ch, addr)
    second = fetch_rugcheck(http, addr) if ch == "solana" else fetch_honeypot(http, ch, addr)
    sources, checks, extra = [], [], {}
    if gp:
        fn = assess_solana if ch == "solana" else assess_evm
        score, critical, checks, extra = fn(gp)
        sources.append(goplus_source(ch, addr, score, critical, checks))
    if isinstance(second, dict):
        try:
            sources.append(assess_rugcheck(second, addr) if ch == "solana" else assess_honeypot(second, ch, addr))
        except (KeyError, TypeError, ValueError):
            pass
    sec = combine_security(sources, checks, extra)
    if sec.get("lp_locked") is None:
        sec["lp_locked"] = next((x.get("lp_locked") for x in sources if x.get("lp_locked") is not None), None)
    return sec


def gem_dex(pairs, address):
    base = summarize_dex(pairs, address)
    if not base:
        return None
    mine = [p for p in pairs if ((p.get("baseToken") or {}).get("address") or "").lower() == address.lower()]
    base["volume6"] = sum(num((p.get("volume") or {}).get("h6")) or 0 for p in mine)
    info = next((p.get("info") for p in mine if p.get("info")), None) or {}
    base["websites"] = [w.get("url") for w in (info.get("websites") or []) if isinstance(w, dict) and w.get("url")][:2]
    base["socials"] = [{"type": x.get("type"), "url": x.get("url")} for x in (info.get("socials") or [])
                       if isinstance(x, dict) and x.get("url")][:3]
    base["boosts"] = max((num((p.get("boosts") or {}).get("active")) or 0) for p in mine)
    return base


def gem_safe(sec, ch, c):
    """Filtro de seguridad duro para micro-caps: todo limpio, sin acuñación ni congelación, sin impuestos."""
    if sec.get("level") != "limpio":
        return False, "contrato no limpio en todos los auditores"
    if (sec.get("top10") or 0) > GEM_RULES["max_top10"]:
        return False, "demasiada concentración en el top 10"
    if max(sec.get("buy_tax") or 0, sec.get("sell_tax") or 0) > GEM_RULES["max_tax"]:
        return False, "impuestos de compra o venta"
    lp = sec.get("lp_locked")
    if lp is not None and lp < GEM_RULES["min_lp_locked"] and not (sec.get("cex") and (c.get("age_days") or 0) >= 180):
        return False, "liquidez sin bloquear"
    if (c.get("dex") or {}).get("boosts") and (c.get("ch7") or 0) > 100:
        return False, "subida con promoción pagada"
    bad = {x["label"] for x in sec.get("checks", []) if not x["ok"]}
    for must in ("Sin autoridad de acuñación", "Sin autoridad de congelación", "Sin acuñación libre del propietario",
                 "Nadie puede alterar saldos", "El propietario no puede alterar saldos"):
        if must in bad:
            return False, must.lower()
    return True, None


def scan_gems(http, coins, excluded, trend_ids, prog, stats):
    lo, hi = GEM_RANGE
    raw = {}
    for page in range(1, 5):
        prog(f"Shitcoins: monedas con más volumen ({page}/4)", 0.88 + 0.01 * page)
        data = http.get(f"{CG}/coins/markets?vs_currency=usd&order=volume_desc&per_page=250&page={page}"
                        f"&sparkline=true&price_change_percentage=1h,24h,7d,30d,1y", ttl=1500) or []
        for r in data:
            if r.get("id"):
                raw.setdefault(r["id"], r)
    for cid, c in coins.items():
        raw.setdefault(cid, c["raw"])
    platforms = fetch_platforms(http)
    cands = []
    for cid, r in raw.items():
        mc = num(r.get("market_cap")) or 0
        if not (lo <= mc < hi):
            continue
        stats["gem_universo"] += 1
        name = r.get("name") or cid
        vol = num(r.get("total_volume")) or 0
        if cid in excluded or EXCLUDE_NAME.search(name) or vol < GEM_RULES["min_vol"]:
            continue
        spark = (r.get("sparkline_in_7d") or {}).get("price") or []
        ts = trend_stats(spark)
        ch7 = num(r.get("price_change_percentage_7d_in_currency"))
        if ts is None or ch7 is None or (abs(ch7) < 1.5 and ts["cv"] < 0.006):
            continue
        ch, addr = None, None
        for k in CHAIN_PRIORITY:
            if (platforms.get(cid) or {}).get(k):
                ch, addr = k, platforms[cid][k]
                break
        if not addr:
            continue
        sectors = (coins.get(cid) or {}).get("sectors") or set()
        cands.append({
            "id": cid, "symbol": (r.get("symbol") or "").upper(), "name": name, "image": r.get("image"),
            "rank": r.get("market_cap_rank"), "sector": min(sectors, key=lambda x: SECTOR_INDEX[x]) if sectors else "otros",
            "bucket": "micro", "price": num(r.get("current_price")), "mcap": mc,
            "fdv": num(r.get("fully_diluted_valuation")), "volume": vol, "turnover": vol / mc,
            "ch24": num(r.get("price_change_percentage_24h_in_currency")), "ch7": ch7,
            "ch30": num(r.get("price_change_percentage_30d_in_currency")),
            "ch1y": num(r.get("price_change_percentage_1y_in_currency")),
            "ath": num(r.get("ath")), "ath_dd": num(r.get("ath_change_percentage")), "ath_date": r.get("ath_date"),
            "trend": ts, "spark": downsample(spark), "trending": cid in trend_ids,
            "contract": {"chain": ch, "address": addr},
            "fdv_ratio": (num(r.get("fully_diluted_valuation")) or 0) / mc if r.get("fully_diluted_valuation") else None,
        })
    stats["gem_liquidas"] = len(cands)
    if not cands:
        return [], []
    R7, R30 = Ranker([c["ch7"] for c in cands]), Ranker([c["ch30"] for c in cands])
    for c in cands:
        t = c["turnover"]
        turn = clamp(100 - abs(math.log10(max(t, 1e-4)) - math.log10(0.6)) * 70)
        c["pre"] = (0.35 * R7(c["ch7"]) + 0.2 * (R30(c["ch30"]) if c["ch30"] is not None else 50) + 0.25 * turn
                    + 0.2 * (50 + 50 * c["trend"]["r2"] * (1 if c["trend"]["slope7"] > 0 else -1)))
    pool = sorted(cands, key=lambda c: -c["pre"])[:150]

    prog(f"Shitcoins: liquidez on-chain de {len(pool)} candidatas", 0.93)
    by_chain = defaultdict(list)
    for c in pool:
        by_chain[CHAINS[c["contract"]["chain"]][1]].append(c["contract"]["address"])
    dex = {}
    for chain, addrs in by_chain.items():
        dex[chain] = fetch_dex_batch(http, chain, addrs)
    rejected = Counter()
    alive = []
    now_ms = time.time() * 1000
    for c in pool:
        d = gem_dex(dex.get(CHAINS[c["contract"]["chain"]][1], {}).get(c["contract"]["address"].lower(), []),
                    c["contract"]["address"])
        if not d:
            rejected["sin pools en DEX"] += 1
            continue
        c["dex"] = d
        c["age_days"] = (now_ms - d["oldest_pool"]) / 86400000 if d.get("oldest_pool") else None
        if d["liquidity"] < GEM_RULES["min_liq"] or d["liquidity"] < GEM_RULES["min_liq_ratio"] * c["mcap"]:
            rejected["liquidez insuficiente"] += 1
        elif c["age_days"] is None or c["age_days"] < GEM_RULES["min_age_days"]:
            rejected["demasiado joven"] += 1
        elif d["buys24"] + d["sells24"] < GEM_RULES["min_txns"]:
            rejected["pocas operaciones"] += 1
        elif c["ch7"] > GEM_RULES["max_ch7"] or (c["ch24"] or 0) > GEM_RULES["max_ch24"]:
            rejected["sobrecalentada (ya subió demasiado)"] += 1
        else:
            alive.append(c)
    stats["gem_con_liquidez"] = len(alive)

    to_audit = sorted(alive, key=lambda c: -c["pre"])[:GEM_RULES["audit"]]
    prog(f"Shitcoins: auditando {len(to_audit)} contratos", 0.95)

    def job(c):
        return c, audit_contract(http, c["contract"]["chain"], c["contract"]["address"])

    safe = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for c, sec in ex.map(job, to_audit):
            c["security"] = sec
            ok, why = gem_safe(sec, c["contract"]["chain"], c)
            if ok:
                safe.append(c)
            else:
                rejected[why] += 1
    stats["gem_auditadas"] = len(to_audit)
    stats["gem_seguras"] = len(safe)
    stats["gem_descartes"] = dict(rejected)
    if not safe:
        return [], cands

    R_tx = Ranker([c["dex"]["buys24"] + c["dex"]["sells24"] for c in alive])
    R_h = Ranker([c["security"].get("holders") for c in safe if c["security"].get("holders")])
    for c in safe:
        d, sec = c["dex"], c["security"]
        rot = d["volume24"] / d["liquidity"] if d["liquidity"] else 0
        rot_s = 100 * rot / 0.5 if rot < 0.5 else (100 if rot <= 6 else clamp(100 - (rot - 6) * 4, 40, 100))
        bp = clamp(50 + ((d.get("buy_ratio") or 1) - 1) * 200)
        accel = (d["volume6"] * 4 / d["volume24"]) if d["volume24"] else 1.0
        c["accel"] = accel
        tr = (rot_s + R_tx(d["buys24"] + d["sells24"]) + bp) / 3
        mo = (0.35 * R7(c["ch7"]) + 0.25 * (R30(c["ch30"]) if c["ch30"] is not None else 50)
              + 0.2 * (50 + 50 * c["trend"]["r2"] * (1 if c["trend"]["slope7"] > 0 else -1))
              + 0.2 * clamp(50 + (accel - 1) * 50))
        liq_ratio = d["liquidity"] / c["mcap"]
        so = mean_present([clamp(liq_ratio / 0.15 * 100), clamp(math.log(max(c["age_days"], 1)) / math.log(365) * 100),
                           R_h(sec.get("holders")) if sec.get("holders") else None,
                           sec["lp_locked"] * 100 if sec.get("lp_locked") is not None else None])
        c["liq_ratio"] = liq_ratio
        c["scores"] = {"traccion": tr, "momentum": mo, "solidez": so, "seguridad": sec["score"]}
        final = 0.3 * tr + 0.25 * mo + 0.25 * so + 0.2 * sec["score"]
        final += 3 if (d["websites"] or d["socials"]) else 0
        final += 3 if c["trending"] else 0
        final -= 4 if d.get("boosts") else 0
        c["overheated"] = (c["ch24"] or 0) > 60 or c["ch7"] > 150
        if c["overheated"]:
            final *= 0.8
        c["final"] = clamp(final)
        a = {"traccion": tr}
        if c["age_days"] <= 60 and c["ch7"] > 0 and accel >= 1.1 and not c["overheated"]:
            a["despegue"] = 0.5 * mo + 0.5 * clamp(50 + (accel - 1) * 60)
        if c["age_days"] >= 120 and c["ch7"] > 0 and (c["ch30"] or 0) > -10:
            a["superviviente"] = 0.6 * mo + 0.4 * so
        if liq_ratio >= 0.08 and sec["score"] >= 85:
            a["solidez"] = 0.6 * so + 0.4 * sec["score"]
        c["arch"] = {k: clamp(v) for k, v in a.items()}

    # Selección: primero una por motivo, luego por nota; máximo 2 por cadena. Nunca se rellena con
    # monedas que no pasaron los filtros.
    picks, used_chain, used_reason = [], Counter(), Counter()

    def ps(c, a):
        return 0.6 * c["final"] + 0.4 * c["arch"][a]

    def take(c, a):
        c["archetype"], c["pick_score"] = a, ps(c, a)
        picks.append(c)
        used_chain[c["contract"]["chain"]] += 1
        used_reason[a] += 1

    for a in [g["id"] for g in GEM_REASONS]:
        opts = [c for c in safe if a in c["arch"] and c not in picks and used_chain[c["contract"]["chain"]] < 2]
        if opts and len(picks) < GEM_PICKS:
            best = max(opts, key=lambda c: ps(c, a))
            if ps(best, a) >= 55:
                take(best, a)
    for v, c, a in sorted(((ps(c, a), c, a) for c in safe for a in c["arch"]), key=lambda x: -x[0]):
        if len(picks) >= GEM_PICKS:
            break
        if c not in picks and used_chain[c["contract"]["chain"]] < 2 and used_reason[a] < 2 and v >= 50:
            take(c, a)
    picks.sort(key=lambda c: -c["pick_score"])
    return picks, cands


def gem_evidence(c):
    d, sec = c["dex"], c["security"]
    out = []
    tx = d["buys24"] + d["sells24"]
    out.append(("traccion", f"{es_num(tx, 0)} operaciones en 24 h ({es_num(d['buys24'], 0)} compras y "
                            f"{es_num(d['sells24'], 0)} ventas) con {fmt_usd(d['volume24'])} de volumen en DEX."))
    if d["liquidity"]:
        out.append(("traccion", f"El volumen diario rota {fmt_x(d['volume24'] / d['liquidity'])} su liquidez "
                                f"({fmt_usd(d['liquidity'])}, el {es_num(c['liq_ratio'] * 100, 1)} % de su capitalización)."))
    if c.get("accel") and c["accel"] >= 1.1:
        out.append(("despegue", f"El volumen de las últimas 6 h va a un ritmo {fmt_x(c['accel'])} superior a la media del día."))
    out.append(("superviviente" if c["age_days"] >= 120 else "despegue",
                f"Su primer pool tiene {es_num(c['age_days'], 0)} días: ha superado la fase en la que ocurren la mayoría de los rug pulls."))
    out.append(("tendencia", f"{fmt_pct(c['ch7'])} en 7 días y {fmt_pct(c['ch30'])} en 30, "
                             f"tendencia {'limpia' if c['trend']['r2'] > 0.6 else 'irregular'} (R² {es_num(c['trend']['r2'], 2)})."))
    names = " y ".join(x["name"] for x in sec.get("sources", []) if x["score"] is not None)
    lock = f", liquidez bloqueada al {es_num(sec['lp_locked'] * 100, 0)} %" if sec.get("lp_locked") else ""
    out.append(("solidez", f"Contrato limpio en {sec.get('consensus')} auditores ({names}): sin acuñación, sin congelación, "
                           f"impuestos ≤ 1 %{lock}."))
    if sec.get("holders"):
        out.append(("solidez", f"{es_num(sec['holders'], 0)} holders; el top 10 sin etiquetar tiene el "
                               f"{es_num((sec.get('top10') or 0) * 100, 0)} %."))
    if d["websites"] or d["socials"]:
        out.append(("solidez", "Web y redes sociales reclamadas en DexScreener."))
    if c["trending"]:
        out.append(("traccion", "En tendencia hoy en CoinGecko."))
    first = [t for k, t in out if k == c["archetype"]]
    rest = [t for k, t in out if k != c["archetype"]]
    return (first + rest)[:7]


def gem_risks(c):
    d, sec = c["dex"], c["security"]
    out = [("alto", "Micro-cap: puede perder la mayor parte de su valor en horas. Solo dinero que puedas perder entero.")]
    if c["overheated"]:
        out.append(("alto", f"Sobrecalentado: {fmt_pct(c['ch24'])} en 24 h. Entrar ahora es perseguir el precio."))
    if c["age_days"] < 30:
        out.append(("alto", f"Muy joven: {es_num(c['age_days'], 0)} días de historia."))
    if d.get("boosts"):
        out.append(("medio", "Tiene promoción pagada activa en DexScreener: parte del interés puede ser comprado."))
    if not (d["websites"] or d["socials"]):
        out.append(("medio", "Sin web ni redes reclamadas en DexScreener: equipo anónimo o poco activo."))
    if (sec.get("top10") or 0) > 0.2:
        out.append(("medio", f"El top 10 sin etiquetar concentra el {es_num(sec['top10'] * 100, 0)} %: un par de ventas grandes mueven el precio."))
    if sec.get("lp_locked") is not None and sec["lp_locked"] < 0.5:
        out.append(("medio", f"Solo el {es_num(sec['lp_locked'] * 100, 0)} % de la liquidez está bloqueada: podría retirarse."))
    if c["liq_ratio"] < 0.06:
        out.append(("medio", f"Liquidez justa para su tamaño ({es_num(c['liq_ratio'] * 100, 1)} % de la capitalización)."))
    if c["trend"]["vol_daily"] and c["trend"]["vol_daily"] > 0.1:
        out.append(("medio", f"Oscilación diaria típica del {es_num(c['trend']['vol_daily'] * 100, 0)} %."))
    if c["fdv_ratio"] and c["fdv_ratio"] > 1.5:
        out.append(("medio", f"FDV {fmt_x(c['fdv_ratio'])} la capitalización: hay suministro por desbloquear."))
    return out[:7]


def pack_gem(c):
    d = c["dex"]
    links = {"coingecko": f"https://www.coingecko.com/es/monedas/{c['id']}",
             "web": d["websites"][0] if d["websites"] else None,
             "x": next((x["url"] for x in d["socials"] if x.get("type") in ("twitter", "x")), None)}
    return {
        **{k: c.get(k) for k in ("id", "symbol", "name", "image", "sector", "bucket", "rank", "price", "mcap", "fdv",
                                 "volume", "turnover", "ch24", "ch7", "ch30", "ch1y", "ath", "ath_dd", "ath_date",
                                 "trending", "overheated", "contract", "archetype", "fdv_ratio")},
        "score": round(c["final"], 1), "pick_score": round(c["pick_score"], 1), "gem": True,
        "age_days": round(c["age_days"], 1), "liq_ratio": c["liq_ratio"], "accel": c.get("accel"),
        "arch": {k: round(v, 1) for k, v in c["arch"].items()},
        "scores": {k: round(v, 1) if v is not None else None for k, v in c["scores"].items()},
        "coverage": 1.0, "trend": {k: (round(v, 4) if v is not None else None) for k, v in c["trend"].items()},
        "spark": [round(x, 12) for x in c["spark"]], "security": c["security"], "dex": d, "links": links,
        "evidence": gem_evidence(c), "risks": [{"level": lv, "text": t} for lv, t in gem_risks(c)],
    }


# ---------------------------------------------------------------------------
# Seguimiento de aciertos
# ---------------------------------------------------------------------------

def parse_ts(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return 0.0


def load_history():
    out = []
    if not os.path.isdir(HISTORY_DIR):
        return out
    for fn in sorted(os.listdir(HISTORY_DIR)):
        if not re.match(r"^\d{4}-\d{2}-\d{2}\.json$", fn):
            continue
        try:
            with open(os.path.join(HISTORY_DIR, fn)) as f:
                d = json.load(f)
            if d.get("picks") and d.get("generated_at"):
                out.append(d)
        except (OSError, json.JSONDecodeError):
            log(f"  historial ilegible: {fn}")
    return out


def cohort_perf(h, prices_then_ids, prices_now, btc_now):
    """Rendimiento equiponderado de las selecciones de una cohorte frente a BTC y al universo."""
    rets = []
    for p in h["picks"]:
        p0, p1 = num(p.get("price")), prices_now.get(p["id"])
        if p0 and p1:
            rets.append({"id": p["id"], "symbol": p["symbol"], "bucket": p.get("bucket"),
                         "archetype": p.get("archetype"), "ret": (p1 / p0 - 1) * 100})
    if not rets:
        return None
    btc = (btc_now / h["btc_price"] - 1) * 100 if btc_now and h.get("btc_price") else None
    uni = [(prices_now[i] / v - 1) * 100 for i, v in (h.get("prices") or {}).items()
           if v and prices_now.get(i) and i in prices_then_ids]
    avg = sum(x["ret"] for x in rets) / len(rets)
    return {
        "n": len(rets), "avg": avg, "median": statistics.median(x["ret"] for x in rets),
        "btc": btc, "universe": statistics.median(uni) if len(uni) >= 20 else None,
        "hit": (sum(1 for x in rets if x["ret"] > btc) / len(rets) * 100) if btc is not None else None,
        "excess": (avg - btc) if btc is not None else None,
        "best": max(rets, key=lambda x: x["ret"]), "worst": min(rets, key=lambda x: x["ret"]),
        "picks": sorted(rets, key=lambda x: -x["ret"]),
    }


def compute_tracking(history, now_prices, btc_now, now):
    by_date = {h["date"]: h for h in history}
    cohorts = []
    for h in sorted(history, key=lambda x: x["date"], reverse=True)[:90]:
        perf = cohort_perf(h, set((h.get("prices") or {}).keys()), now_prices, btc_now)
        if perf:
            age = (now.timestamp() - parse_ts(h["generated_at"])) / 86400
            gp = cohort_perf({**h, "picks": h["gems"]}, set(), now_prices, btc_now) if h.get("gems") else None
            perf["gems"] = {"n": gp["n"], "avg": gp["avg"], "best": gp["best"], "worst": gp["worst"]} if gp else None
            cohorts.append({"date": h["date"], "age_days": round(age, 2), **perf})
    horizons = {}
    for H in HORIZONS:
        samples = []
        for h in history:
            d0 = datetime.fromisoformat(h["date"])
            for slack in (0, 1, -1, 2):
                later = by_date.get((d0 + timedelta(days=H + slack)).strftime("%Y-%m-%d"))
                if later:
                    pr = {k: v for k, v in (later.get("prices") or {}).items() if v}
                    perf = cohort_perf(h, set((h.get("prices") or {}).keys()) & set(pr), pr, later.get("btc_price"))
                    if perf:
                        samples.append(perf)
                    break
        first = min((h["date"] for h in history), default=None)
        entry = {"cohorts": len(samples),
                 "first_result": (datetime.fromisoformat(first) + timedelta(days=H)).strftime("%Y-%m-%d") if first else None}
        if samples:
            def avg_of(k):
                v = [x[k] for x in samples if x[k] is not None]
                return sum(v) / len(v) if v else None
            entry.update({k: avg_of(k) for k in ("avg", "btc", "universe", "hit", "excess")})
            entry["beat_btc_cohorts"] = sum(1 for x in samples if (x["excess"] or 0) > 0)
        horizons[str(H)] = entry
    return {"cohorts": cohorts, "horizons": horizons, "track_days": TRACK_DAYS}


# ---------------------------------------------------------------------------
# Orquestación
# ---------------------------------------------------------------------------

def run_scan(use_cache=True, progress=None):
    t0 = time.time()
    progress = progress or (lambda stage, p: None)

    def prog(stage, p):
        log(stage)
        progress(stage, p)
        set_status(stage, p)

    http = Http(use_cache=use_cache)
    prog("Contexto de mercado", 0.01)
    market, trend_ids = fetch_context(http)
    coins, excluded = fetch_universe(http, prog)
    prog("DefiLlama: TVL, comisiones e ingresos", 0.41)
    llama = fetch_defillama(http)
    prog("Calculando métricas del universo", 0.45)
    recs, stats = build_records(coins, excluded, llama, trend_ids)
    sector_stats, R = score_market(recs, market)
    short = shortlist(recs, R)
    stats["preseleccion"] = len(short)
    log(f"Universo {stats['universo']} · elegibles {len(recs)} · preselección {len(short)}")

    # Enriquecimiento de la preselección
    details = {}
    for i, r in enumerate(short):
        prog(f"Ficha de {r['symbol']} ({i + 1}/{len(short)})", 0.46 + 0.30 * i / max(1, len(short)))
        details[r["id"]] = fetch_detail(http, r["id"]) or {}

    sec_jobs, dex_by_chain = [], defaultdict(list)
    for r in short:
        d = details.get(r["id"]) or {}
        ch, addr, native = pick_contract(d)
        r["native"] = native
        r["contract"] = {"chain": ch, "address": addr} if addr else None
        r["watchlist"] = num(d.get("watchlist_portfolio_users"))
        r["sentiment_up"] = num(d.get("sentiment_votes_up_percentage"))
        r["categories"] = [c for c in (d.get("categories") or []) if c][:8]
        desc = re.sub(r"<[^>]+>", "", ((d.get("description") or {}).get("en") or "")).strip()
        r["description"] = re.sub(r"\s+", " ", desc)[:420]
        links = d.get("links") or {}
        hp = [u for u in (links.get("homepage") or []) if u]
        r["links"] = {
            "web": hp[0] if hp else None,
            "x": f"https://x.com/{links['twitter_screen_name']}" if links.get("twitter_screen_name") else None,
            "coingecko": f"https://www.coingecko.com/es/monedas/{r['id']}",
            "defillama": (f"https://defillama.com/{'chain' if r['llama_kind'] == 'chain' else 'protocol'}/"
                          f"{urllib.parse.quote(str(r['llama_slug']))}") if r.get("llama_slug") else None,
        }
        r["genesis"] = d.get("genesis_date")
        if addr:
            sec_jobs.append(r)
            dex_by_chain[CHAINS[ch][1]].append(addr)

    prog(f"Seguridad: {len(sec_jobs)} contratos en GoPlus, Honeypot.is y RugCheck", 0.77)

    def do_sec(r):
        ch, addr = r["contract"]["chain"], r["contract"]["address"]
        gp = fetch_security(http, ch, addr)
        second = fetch_rugcheck(http, addr) if ch == "solana" else fetch_honeypot(http, ch, addr)
        return r, gp, second

    with ThreadPoolExecutor(max_workers=4) as ex:
        for r, gp, second in ex.map(do_sec, sec_jobs):
            ch, addr = r["contract"]["chain"], r["contract"]["address"]
            sources, checks, extra = [], [], {}
            if gp:
                fn = assess_solana if ch == "solana" else assess_evm
                score, critical, checks, extra = fn(gp)
                sources.append(goplus_source(ch, addr, score, critical, checks))
            if second and isinstance(second, dict):
                try:
                    sources.append(assess_rugcheck(second, addr) if ch == "solana" else assess_honeypot(second, ch, addr))
                except (KeyError, TypeError, ValueError) as e:
                    log(f"  {r['symbol']}: respuesta de seguridad no interpretable ({e})")
            r["security"] = combine_security(sources, checks, extra)

    prog("DexScreener: liquidez on-chain", 0.86)
    dex_data = {}
    for chain, addrs in dex_by_chain.items():
        dex_data[chain] = fetch_dex_batch(http, chain, addrs)
    for r in short:
        if r.get("native"):
            r["security"] = {"level": "nativo", "score": 80, "critical": False, "checks": []}
        elif not r.get("security"):
            r["security"] = {"level": "sin_datos", "score": 60, "critical": False, "checks": []}
        if r.get("contract"):
            chain = CHAINS[r["contract"]["chain"]][1]
            pairs = dex_data.get(chain, {}).get(r["contract"]["address"].lower(), [])
            r["dex"] = summarize_dex(pairs, r["contract"]["address"])
            if r["dex"]:
                r["buy_ratio"] = r["dex"]["buy_ratio"]

    # Atención relativa (seguidores por dólar de capitalización) dentro de la preselección
    wpm = [math.log(r["watchlist"] / (r["mcap"] / 1e6)) for r in short if r.get("watchlist")]
    R_w = Ranker(wpm)
    med_w = math.exp(statistics.median(wpm)) if wpm else None
    for r in short:
        if r.get("watchlist"):
            v = r["watchlist"] / (r["mcap"] / 1e6)
            r["_watch_pr"] = R_w(math.log(v))
            r["watch_rel"] = v / med_w if med_w else None
            att = r["_watch_pr"]
            if r["trending"]:
                att += 25
            if (r.get("sentiment_up") or 0) >= 85:
                att += 5
            if (r.get("buy_ratio") or 0) > 1.15:
                att += 8
            r["scores"]["atencion"] = clamp(att)
        r["scores"]["seguridad"] = r["security"]["score"]
        # liquidez on-chain como ajuste fino
        if r.get("dex") and not r.get("native"):
            liq = r["dex"]["liquidity"]
            adj = -15 if liq < 100e3 else (-6 if liq < 300e3 else (5 if liq > 3e6 else 0))
            r["scores"]["liquidez"] = clamp(r["scores"]["liquidez"] + adj)
        r["final"], r["coverage"] = composite(r["scores"])
        if r["overheated"]:
            r["final"] *= 0.9
        if r["security"]["level"] == "riesgo":
            r["final"] *= 0.6
        r["arch"] = archetype_scores(r, R)

    stats["auditados"] = sum(1 for r in short if r["security"]["level"] not in ("nativo", "sin_datos"))
    stats["auditorias_cruzadas"] = sum(1 for r in short if len([x for x in r["security"].get("sources", [])
                                                               if x["score"] is not None]) >= 2)
    stats["discrepancias"] = sum(1 for r in short if r["security"].get("disagree"))
    stats["descartados_seguridad"] = sum(1 for r in short if r["security"]["level"] == "riesgo")
    def thin(r):
        # Liquidez en DEX ridícula para su tamaño y sin listado conocido en exchanges centralizados.
        d = r.get("dex")
        return (bool(d) and not r.get("native") and not r["security"].get("cex")
                and d["liquidity"] < max(60e3, 0.0005 * r["mcap"]))
    # Candidatos: sin riesgo de contrato ni liquidez on-chain ridícula. Los que no encajan en
    # ningún motivo solo entran si algún tramo se queda corto (fase 3 de select).
    cands = [r for r in short if r["security"]["level"] != "riesgo" and not thin(r)]
    stats["descartados_liquidez_onchain"] = sum(1 for r in short if thin(r))
    picks = select(cands)
    prog("Redactando conclusiones", 0.95)

    def pack(r, full=False):
        base = {
            "id": r["id"], "symbol": r["symbol"], "name": r["name"], "image": r["image"],
            "sector": r["sector"], "bucket": r["bucket"], "rank": r["rank"],
            "price": r["price"], "mcap": r["mcap"], "fdv": r["fdv"], "volume": r["volume"],
            "ch24": r["ch24"], "ch7": r["ch7"], "ch30": r["ch30"], "ch1y": r["ch1y"],
            "score": round(r.get("final", r["pre"]), 1), "enriched": "final" in r,
            "arch": {k: round(v, 1) for k, v in (r.get("arch") or archetype_scores(r, R)).items()},
        }
        if not full:
            return base
        ts = r["trend"]
        ev = evidence(r, sector_stats, market)
        prim = [e for e in ev if e[1] == r["archetype"]]
        rest = sorted([e for e in ev if e[1] != r["archetype"]], key=lambda e: -e[0])
        base.update({
            "archetype": r["archetype"], "pick_score": round(r["pick_score"], 1),
            "sectors": r["sectors"], "categories": r.get("categories"),
            "turnover": r["turnover"], "fdv_ratio": r["fdv_ratio"], "circ_ratio": r["circ_ratio"],
            "ath": r["ath"], "ath_dd": r["ath_dd"], "ath_date": r["ath_date"], "atl_up": r["atl_up"],
            "tvl": r["tvl"], "tvl_ch7": r["tvl_ch7"], "fees30": r["fees30"], "fees_growth": r["fees_growth"],
            "rev30": r["rev30"], "rev_growth": r["rev_growth"], "mcap_tvl": r["mcap_tvl"], "pf": r["pf"],
            "ps": r["ps"], "rev_yield": r["rev_yield"], "llama_cat": r["llama_cat"], "tvl_skewed": r["tvl_skewed"],
            "trend": {k: (round(v, 4) if v is not None else None) for k, v in ts.items()},
            "rel30": r["rel30"], "vs_btc30": r["vs_btc30"], "turn_rel": r["turn_rel"],
            "trending": r["trending"], "watchlist": r.get("watchlist"), "watch_rel": r.get("watch_rel"),
            "sentiment_up": r.get("sentiment_up"), "overheated": r["overheated"],
            "spark": [round(x, 10) for x in r["spark"]],
            "scores": {k: (round(v, 1) if v is not None else None) for k, v in r["scores"].items()},
            "coverage": round(r["coverage"], 2),
            "security": r["security"], "contract": r.get("contract"), "native": r.get("native"),
            "dex": r.get("dex"), "description": r.get("description"), "links": r.get("links"),
            "genesis": r.get("genesis"),
            "evidence": [e[2] for e in (prim + rest)][:6],
            "risks": [{"level": lv, "text": t} for lv, t in risks(r)][:6],
        })
        return base

    radar = sorted(recs, key=lambda r: -(r.get("final", r["pre"])))

    try:
        gems, gem_pool = scan_gems(http, coins, excluded, trend_ids, prog, stats)
    except Exception as e:  # noqa: BLE001 — la zona shitcoin nunca debe tumbar el escaneo principal
        log(f"Zona shitcoin: error {type(e).__name__}: {e}")
        gems, gem_pool = [], []
    log(f"Zona shitcoin: {len(gems)} joyas de {stats.get('gem_universo', 0)} micro-caps")

    # Seguimiento de aciertos: una cohorte por día (la primera selección del día UTC).
    prog("Seguimiento de selecciones anteriores", 0.97)
    history = load_history()
    now_prices = {cid: num(c["raw"].get("current_price")) for cid, c in coins.items()
                  if num(c["raw"].get("current_price"))}
    for c in gem_pool:
        if c.get("price"):
            now_prices.setdefault(c["id"], c["price"])
    tracked = {p["id"] for p in picks} | {g["id"] for g in gems}
    cutoff = time.time() - TRACK_DAYS * 86400
    for h in history:
        if parse_ts(h["generated_at"]) >= cutoff:
            tracked |= {p["id"] for p in h["picks"]} | {g["id"] for g in h.get("gems", [])}
    missing = sorted(i for i in tracked if i not in now_prices)
    for i in range(0, len(missing), 200):
        sp = http.get(f"{CG}/simple/price?ids={','.join(missing[i:i + 200])}&vs_currencies=usd", ttl=600) or {}
        for cid, v in sp.items():
            if num((v or {}).get("usd")):
                now_prices[cid] = num(v["usd"])
    generated = datetime.now(timezone.utc)
    day = generated.strftime("%Y-%m-%d")
    if not any(h["date"] == day for h in history):
        snap = {
            "date": day, "generated_at": generated.isoformat(timespec="seconds"),
            "btc_price": market.get("btc_price"),
            "picks": [{"id": r["id"], "symbol": r["symbol"], "bucket": r["bucket"], "sector": r["sector"],
                       "archetype": r["archetype"], "score": round(r["final"], 1), "price": r["price"]}
                      for r in picks],
            "gems": [{"id": g["id"], "symbol": g["symbol"], "archetype": g["archetype"],
                      "score": round(g["final"], 1), "price": g["price"]} for g in gems],
            "prices": {cid: float(f"{now_prices[cid]:.6g}") for cid in sorted({r["id"] for r in recs} | tracked)
                       if cid in now_prices},
        }
        os.makedirs(HISTORY_DIR, exist_ok=True)
        with open(os.path.join(HISTORY_DIR, f"{day}.json"), "w") as f:
            json.dump(snap, f, ensure_ascii=False, separators=(",", ":"))
        history.append(snap)
        log(f"Nueva cohorte diaria guardada: {day}")
    tracking = compute_tracking(history, now_prices, market.get("btc_price"), generated)
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - t0, 1),
        "market": market,
        "config": {"buckets": BUCKETS, "sectors": [{"id": s["id"], "label": s["label"]} for s in SECTORS],
                   "archetypes": ARCHETYPES, "weights": WEIGHTS, "max_per_sector": MAX_PER_SECTOR,
                   "max_per_archetype": MAX_PER_ARCHETYPE, "missing_value": MISSING_DEFAULT,
                   "horizons": list(HORIZONS), "gem_reasons": GEM_REASONS, "gem_rules": GEM_RULES,
                   "gem_range": list(GEM_RANGE)},
        "stats": dict(stats) | {"api_calls": dict(http.calls), "api_errors": dict(http.errors)},
        "sector_stats": sector_stats,
        "picks": [pack(r, True) for r in picks],
        "tracking": tracking,
        "gems": [pack_gem(g) for g in gems],
        "radar": [pack(r) for r in radar],
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "scan.json"), "w") as f:
        json.dump(result, f, ensure_ascii=False, default=lambda o: sorted(o) if isinstance(o, set) else None)
    build_ui(result)
    set_status("Listo", 1.0, running=False)
    log(f"Escaneo completo en {result['duration_s']} s · {len(picks)} selecciones")
    return result


# ---------------------------------------------------------------------------
# Interfaz
# ---------------------------------------------------------------------------

def repo_slug():
    """owner/repo de GitHub, para el botón «Re-escanear» de la web."""
    slug = os.environ.get("GITHUB_REPOSITORY")
    if slug:
        return slug
    try:
        with open(os.path.join(ROOT, ".git", "config")) as f:
            m = re.search(r"github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?\s", f.read())
        return m.group(1) if m else None
    except OSError:
        return None


def build_ui(result=None):
    if result is None:
        with open(os.path.join(DATA_DIR, "scan.json")) as f:
            result = json.load(f)
    result.setdefault("config", {})["repo"] = repo_slug()
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()
    payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    page = tpl.replace("/*__SCAN_DATA__*/null", payload)
    os.makedirs(DIST_DIR, exist_ok=True)
    # Fragmento (para publicar como Artifact) y documento completo (para abrir en local).
    with open(os.path.join(DIST_DIR, "artifact.html"), "w", encoding="utf-8") as f:
        f.write(page)
    with open(os.path.join(DIST_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write('<!doctype html>\n<html lang="es">\n<head>\n<meta charset="utf-8">\n'
                '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
                '</head>\n<body>\n' + page + "\n</body>\n</html>\n")
    # Copia para GitHub Pages (carpeta docs/)
    docs = os.path.join(ROOT, "docs")
    os.makedirs(docs, exist_ok=True)
    with open(os.path.join(DIST_DIR, "index.html"), encoding="utf-8") as src, \
            open(os.path.join(docs, "index.html"), "w", encoding="utf-8") as dst:
        dst.write(src.read())
    open(os.path.join(docs, ".nojekyll"), "w").close()
    with open(os.path.join(docs, "scan.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, separators=(",", ":"))
    log(f"Interfaz generada en {os.path.join(DIST_DIR, 'index.html')} y docs/index.html")


def serve(port, host="127.0.0.1"):
    import http.server

    state = {"thread": None}

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=DIST_DIR, **k)

        def log_message(self, fmt, *args):
            pass

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/api/status"):
                try:
                    with open(STATUS_PATH) as f:
                        st = json.load(f)
                except (OSError, json.JSONDecodeError):
                    st = {"running": False, "stage": None}
                st["running"] = bool(state["thread"] and state["thread"].is_alive())
                return self._json(200, st)
            return super().do_GET()

        def do_POST(self):
            if self.path.startswith("/api/scan"):
                if state["thread"] and state["thread"].is_alive():
                    return self._json(409, {"error": "Ya hay un escaneo en marcha"})

                def job():
                    try:
                        run_scan(use_cache=False)
                    except Exception as e:  # noqa: BLE001
                        set_status(f"Error: {e}", 1.0, running=False, error=str(e))
                        log(f"Error en el escaneo: {e}")

                set_status("Iniciando", 0.0)
                state["thread"] = threading.Thread(target=job, daemon=True)
                state["thread"].start()
                return self._json(202, {"ok": True})
            self.send_error(404)

    if not os.path.exists(os.path.join(DIST_DIR, "index.html")):
        if os.path.exists(os.path.join(DATA_DIR, "scan.json")):
            build_ui()
        else:
            log("No hay escaneo previo: lanzando el primero…")
            run_scan()
    srv = http.server.ThreadingHTTPServer((host, port), H)
    log(f"Token Sniffer en http://localhost:{port}")
    srv.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="Token Sniffer: 16 criptoactivos con potencial por motivos distintos")
    ap.add_argument("cmd", nargs="?", default="scan", choices=["scan", "serve"])
    ap.add_argument("--no-cache", action="store_true", help="ignora la caché local de respuestas")
    ap.add_argument("--build-only", action="store_true", help="regenera la interfaz con el último escaneo")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1", help="interfaz de red del servidor (0.0.0.0 para exponerlo)")
    a = ap.parse_args()
    if a.cmd == "serve":
        return serve(a.port, a.host)
    if a.build_only:
        return build_ui()
    run_scan(use_cache=not a.no_cache)


if __name__ == "__main__":
    main()
