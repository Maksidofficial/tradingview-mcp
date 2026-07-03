#!/usr/bin/env python3
"""Live signal check for the Liquidity Scalp Bot — evaluates the CURRENT bar.

Fetches fresh BTCUSDT-perp 5m candles from OKX, replays the strategy state
(pools, sweeps, filters), and reports what the bot sees right now:
nearest liquidity pools, sweep events on recent bars, and whether an entry
would fire — with entry/stop/target if so.

Usage: python3 backtest/signal_now.py [param=value ...]
"""
import json
import sys
import time
import urllib.request
from datetime import datetime, timezone

from backtest_scalp import DEFAULTS, precompute

INST = "BTC-USDT-SWAP"
BAR = "5m"


def fetch_recent(n_bars=600):
    rows = {}
    after = ""
    while len(rows) < n_bars:
        url = f"https://www.okx.com/api/v5/market/candles?instId={INST}&bar={BAR}&limit=300"
        if after:
            url = url.replace("/candles", "/history-candles").replace("limit=300", "limit=100") + f"&after={after}"
        req = urllib.request.Request(url, headers={"User-Agent": "signal/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read())
        data = payload.get("data", [])
        if not data:
            break
        for r in data:
            rows[int(r[0])] = dict(ts=int(r[0]) // 1000, o=float(r[1]), h=float(r[2]),
                                   l=float(r[3]), c=float(r[4]), v=float(r[5]))
        after = data[-1][0]
        time.sleep(0.12)
    return [rows[k] for k in sorted(rows)]


def main():
    p = dict(DEFAULTS)
    for a in sys.argv[1:]:
        if "=" in a:
            k, v = a.split("=", 1)
            p[k] = type(DEFAULTS[k])(float(v)) if isinstance(DEFAULTS[k], (int, float)) else v

    print("Fetching latest candles from OKX...", file=sys.stderr)
    bars = fetch_recent()
    d = precompute(bars, p)
    n = d["n"]
    o, h, l, c = d["o"], d["h"], d["l"], d["c"]
    lb = p["liq_lb"]

    # replay pool tracking over history
    bsl, ssl = [], []
    for i in range(lb * 2, n):
        j = i - lb
        if j >= lb:
            if h[j] == max(h[j - lb:j + lb + 1]):
                bsl.insert(0, h[j])
                del bsl[p["max_pools"]:]
            if l[j] == min(l[j - lb:j + lb + 1]):
                ssl.insert(0, l[j])
                del ssl[p["max_pools"]:]

    i = n - 1  # current (possibly still-forming) bar
    px = c[i]
    atr = d["atr"][i]
    g = p["round_grid"]
    rup = (int(px // g) + 1) * g
    rdn = int(px // g) * g
    now = datetime.fromtimestamp(bars[i]["ts"], tz=timezone.utc)

    def pools_below():
        out = [(x, "swing") for x in ssl if x < px]
        if p["use_pdhl"] and d["pdl"][i] is not None and d["pdl"][i] < px:
            out.append((d["pdl"][i], "PDL"))
        if p["use_round"]:
            out += [(rdn, "round"), (rdn - g, "round")]
        return sorted(out, reverse=True)

    def pools_above():
        out = [(x, "swing") for x in bsl if x > px]
        if p["use_pdhl"] and d["pdh"][i] is not None and d["pdh"][i] > px:
            out.append((d["pdh"][i], "PDH"))
        if p["use_round"]:
            out += [(rup, "round"), (rup + g, "round")]
        return sorted(out)

    print(f"\n═══ LIQUIDITY SCALP BOT — LIVE SIGNAL ═══")
    print(f"{INST} {BAR} @ {now:%Y-%m-%d %H:%M} UTC")
    print(f"Price: {px:,.1f}   ATR: {atr:,.1f}   RSI: {d['rsi'][i]:.1f}   "
          f"VWAP: {d['vwap'][i]:,.1f} ({'above' if px > d['vwap'][i] else 'below'})")

    print(f"\nLiquidity above (targets for longs / sweep zones for shorts):")
    for lvl, kind in pools_above()[:4]:
        print(f"  {lvl:>10,.1f}  {kind:<6} (+{(lvl-px)/atr:.1f} ATR)")
    print(f"Liquidity below (targets for shorts / sweep zones for longs):")
    for lvl, kind in pools_below()[:4]:
        print(f"  {lvl:>10,.1f}  {kind:<6} (-{(px-lvl)/atr:.1f} ATR)")

    # sweep scan over last 6 bars
    print(f"\nRecent sweep activity (last 6 bars):")
    any_sweep = False
    for k in range(max(0, i - 5), i + 1):
        pools_dn = [x for x in ssl] + ([d["pdl"][k]] if p["use_pdhl"] and d["pdl"][k] else []) + \
                   ([int(c[k] // g) * g, int(c[k] // g) * g - g] if p["use_round"] else [])
        pools_up = [x for x in bsl] + ([d["pdh"][k]] if p["use_pdhl"] and d["pdh"][k] else []) + \
                   ([(int(c[k] // g) + 1) * g, (int(c[k] // g) + 2) * g] if p["use_round"] else [])
        t = datetime.fromtimestamp(bars[k]["ts"], tz=timezone.utc)
        akr = d["atr"][k]
        for lvl in pools_dn:
            if l[k] < lvl and c[k] > lvl and (lvl - l[k]) >= akr * p["min_pen"]:
                rng = h[k] - l[k]
                cp = (c[k] - l[k]) / rng if rng > 0 else 0.5
                strong = "STRONG reclaim" if cp >= p["reclaim_pos"] else f"weak reclaim ({cp:.0%})"
                print(f"  {t:%H:%M}  SSL SWEEP @ {lvl:,.1f} — bullish, {strong}")
                any_sweep = True
        for lvl in pools_up:
            if h[k] > lvl and c[k] < lvl and (h[k] - lvl) >= akr * p["min_pen"]:
                rng = h[k] - l[k]
                cp = (c[k] - l[k]) / rng if rng > 0 else 0.5
                strong = "STRONG reclaim" if cp <= 1 - p["reclaim_pos"] else f"weak reclaim ({1-cp:.0%})"
                print(f"  {t:%H:%M}  BSL SWEEP @ {lvl:,.1f} — bearish, {strong}")
                any_sweep = True
    if not any_sweep:
        print("  none")

    # evaluate entry on current bar (sweep-reclaim mode)
    rng = h[i] - l[i]
    cp = (c[i] - l[i]) / rng if rng > 0 else 0.5
    vol_ok = d["vavg"][i] and d["v"][i] > d["vavg"][i] * p["vol_mult"]

    signal = None
    for lvl, kind in pools_below():
        if l[i] < lvl and c[i] > lvl and (lvl - l[i]) >= atr * p["min_pen"] and cp >= p["reclaim_pos"]:
            stop = l[i] - atr * p["stop_buf"]
            ups = pools_above()
            tgt = min(ups[0][0], px + atr * p["max_tgt_atr"]) if ups else px + atr * p["max_tgt_atr"]
            rr = (tgt - px) / (px - stop) if px > stop else 0
            checks = {"reclaim": True, "volume": bool(vol_ok),
                      f"RSI<{p['rsi_hi']:.0f}": d["rsi"][i] < p["rsi_hi"], "R:R>=1": rr >= p["rr_min"]}
            signal = ("LONG", lvl, kind, stop, tgt, rr, checks)
            break
    if signal is None:
        for lvl, kind in pools_above():
            if h[i] > lvl and c[i] < lvl and (h[i] - lvl) >= atr * p["min_pen"] and cp <= 1 - p["reclaim_pos"]:
                stop = h[i] + atr * p["stop_buf"]
                dns = pools_below()
                tgt = max(dns[0][0], px - atr * p["max_tgt_atr"]) if dns else px - atr * p["max_tgt_atr"]
                rr = (px - tgt) / (stop - px) if stop > px else 0
                checks = {"reclaim": True, "volume": bool(vol_ok),
                          f"RSI>{p['rsi_lo']:.0f}": d["rsi"][i] > p["rsi_lo"], "R:R>=1": rr >= p["rr_min"]}
                signal = ("SHORT", lvl, kind, stop, tgt, rr, checks)
                break

    print()
    if signal:
        side, lvl, kind, stop, tgt, rr, checks = signal
        all_ok = all(checks.values())
        print(f"{'█ SIGNAL: ' + side if all_ok else '░ PARTIAL SETUP: ' + side + ' (filters failing)'}")
        print(f"  Swept pool:  {lvl:,.1f} ({kind})")
        print(f"  Entry:       {px:,.1f}  (limit order at/below this)")
        print(f"  Stop:        {stop:,.1f}  ({abs(px-stop)/px*100:.2f}%)")
        print(f"  Target:      {tgt:,.1f}  ({abs(tgt-px)/px*100:.2f}%)")
        print(f"  R:R:         {rr:.2f}")
        for name, ok in checks.items():
            print(f"  {'✓' if ok else '✗'} {name}")
        print(f"  Max hold: {p['max_hold']} bars ({p['max_hold']*5} min). Move stop to BE at +1R.")
    else:
        print("░ NO SIGNAL — no qualifying sweep on the current bar.")
        print("  Watch the sweep zones listed above; a wick through one that closes")
        print("  back inside with a strong reclaim is the trigger.")
    print()


if __name__ == "__main__":
    main()
