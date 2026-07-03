#!/usr/bin/env python3
"""Offline backtester for the Liquidity Scalp Bot (mirrors pine/scalp_liquidity_bot.pine).

Replays the SWEPT -> ARMED -> ENTRY state machine bar-by-bar over OHLCV data,
with no lookahead: pivots only become usable after they confirm, HTF EMA uses
completed 15m bars, PDH/PDL come from the prior completed UTC day.

Usage:
  python3 backtest/backtest_scalp.py                 # single run, default params
  python3 backtest/backtest_scalp.py --sweep         # coarse parameter sweep
  python3 backtest/backtest_scalp.py disp_atr=1.0 rr_min=1.5   # override params
"""
import csv
import math
import os
import sys
from datetime import datetime, timezone

DATA = os.path.join(os.path.dirname(__file__), "data", "BTC-USDT-SWAP_5m.csv")
DATA_15 = os.path.join(os.path.dirname(__file__), "data", "BTC-USDT-SWAP_15m.csv")

DEFAULTS = dict(
    # liquidity pools
    liq_lb=15, max_pools=3, use_pdhl=1,
    round_grid=500.0, use_round=1,        # round-number pools ($500 grid for BTC)
    # setup sequence
    min_pen=0.15, sweep_win=5, retr_win=5, disp_atr=1.2, ms_lb=3, confirm_close=1,
    # filters
    vol_mult=1.0, rsi_hi=60.0, rsi_lo=30.0,
    use_htf=0, htf_len=50,
    use_vwap=0,        # 0=off, 1=with-trend (long above vwap), 2=reversion (long below vwap = room to revert)
    target_mode="pool",  # "pool" = next liquidity pool; "vwap" = revert to VWAP (falls back to pool)
    use_regime=0, regime_mult=1.0,        # ATR% must exceed regime_mult * rolling median ATR%
    use_kz=0,                             # UTC killzones (off by default for 24/7 crypto)
    # risk
    rr_min=1.0, stop_buf=0.75, max_hold=9, use_be=1, be_trig=1.0,
    max_daily=3, max_loss=2,
    max_tgt_atr=3.5,   # skip trade if pool target further than this (0 = off)
    tp_fallback=1,     # 1 = when pool too far, cap target at max_tgt_atr*ATR instead of skipping
    entry_mode="sweep",    # "retrace" = pullback into zone; "momentum" = displacement close; "sweep" = sweep-reclaim bar itself
    side="both",       # "both" | "long" | "short"
    reclaim_pos=0.5,   # sweep mode: close must be in this fraction of bar range (strength of reclaim)
    scratch_bars=0,    # exit if trade hasn't reached scratch_r after this many bars (0 = off)
    scratch_r=0.0,
    trail_atr=0.0,     # after +1R, trail stop this many ATR behind best price (0 = off)
    bar_min=5,         # bar size in minutes (5 or 15); HTF EMA = 3x bars up
    # costs (fraction per side) — maker-order assumption
    fee=0.0002, slip=0.00005,
)

KILLZONES = [(7, 10), (13, 17)]  # UTC hours: London open, NY open


def load(path):
    bars = []
    with open(path) as f:
        for row in csv.DictReader(f):
            bars.append(dict(
                ts=int(row["ts_ms"]) // 1000,
                o=float(row["open"]), h=float(row["high"]),
                l=float(row["low"]), c=float(row["close"]), v=float(row["volume"])))
    return bars


def precompute(bars, p):
    n = len(bars)
    o = [b["o"] for b in bars]; h = [b["h"] for b in bars]
    l = [b["l"] for b in bars]; c = [b["c"] for b in bars]; v = [b["v"] for b in bars]
    day = [datetime.fromtimestamp(b["ts"], tz=timezone.utc).strftime("%Y%m%d") for b in bars]
    hour = [datetime.fromtimestamp(b["ts"], tz=timezone.utc).hour for b in bars]

    # ATR(14) Wilder
    atr = [None] * n
    trs = []
    for i in range(n):
        tr = h[i] - l[i] if i == 0 else max(h[i] - l[i], abs(h[i] - c[i-1]), abs(l[i] - c[i-1]))
        trs.append(tr)
        if i == 13:
            atr[i] = sum(trs) / 14
        elif i > 13:
            atr[i] = (atr[i-1] * 13 + tr) / 14

    # RSI(14) Wilder
    rsi = [None] * n
    ag = al = None
    for i in range(1, n):
        ch = c[i] - c[i-1]
        g, lo_ = max(ch, 0), max(-ch, 0)
        if i == 14:
            gains = [max(c[j] - c[j-1], 0) for j in range(1, 15)]
            losses = [max(c[j-1] - c[j], 0) for j in range(1, 15)]
            ag, al = sum(gains) / 14, sum(losses) / 14
        elif i > 14:
            ag, al = (ag * 13 + g) / 14, (al * 13 + lo_) / 14
        if i >= 14:
            rsi[i] = 100.0 if al == 0 else 100 - 100 / (1 + ag / al)

    # volume SMA(20)
    vavg = [None] * n
    s = 0.0
    for i in range(n):
        s += v[i]
        if i >= 20:
            s -= v[i-20]
        if i >= 19:
            vavg[i] = s / 20

    # daily-reset VWAP (close-weighted, like ta.vwap(close))
    vwap = [None] * n
    pv = vv = 0.0
    for i in range(n):
        if i == 0 or day[i] != day[i-1]:
            pv = vv = 0.0
        pv += c[i] * v[i]; vv += v[i]
        vwap[i] = pv / vv if vv > 0 else c[i]

    # HTF 15m EMA(htf_len) — uses only COMPLETED 15m bars (no lookahead)
    htf_ema = [None] * n
    ema = None
    k = 2 / (p["htf_len"] + 1)
    closes15 = []
    htf_min = p["bar_min"] * 3
    for i in range(n):
        htf_ema[i] = ema
        ts = bars[i]["ts"]
        if (ts // 60 + p["bar_min"]) % htf_min == 0:  # this bar completes an HTF bar
            closes15.append(c[i])
            if ema is None and len(closes15) == p["htf_len"]:
                ema = sum(closes15) / p["htf_len"]
            elif ema is not None:
                ema = c[i] * k + ema * (1 - k)

    # PDH/PDL from prior completed UTC day
    pdh = [None] * n; pdl = [None] * n
    dhi = {}; dlo = {}
    for i in range(n):
        d = day[i]
        dhi[d] = max(dhi.get(d, -1e18), h[i]); dlo[d] = min(dlo.get(d, 1e18), l[i])
    prev = {}
    days_sorted = sorted(dhi)
    for j in range(1, len(days_sorted)):
        prev[days_sorted[j]] = (dhi[days_sorted[j-1]], dlo[days_sorted[j-1]])
    for i in range(n):
        if day[i] in prev:
            pdh[i], pdl[i] = prev[day[i]]

    # ATR% regime: rolling median of atr/close over last 288 bars (1 day)
    atrpct_med = [None] * n
    win = []
    for i in range(n):
        if atr[i] is not None:
            win.append(atr[i] / c[i])
            if len(win) > 288:
                win.pop(0)
            if len(win) >= 50:
                sw = sorted(win)
                atrpct_med[i] = sw[len(sw) // 2]

    return dict(o=o, h=h, l=l, c=c, v=v, day=day, hour=hour, atr=atr, rsi=rsi,
                vavg=vavg, vwap=vwap, htf_ema=htf_ema, pdh=pdh, pdl=pdl,
                atrpct_med=atrpct_med, n=n)


def run(bars, p, collect_trades=False):
    d = precompute(bars, p)
    n = d["n"]
    o, h, l, c = d["o"], d["h"], d["l"], d["c"]
    lb, ms = p["liq_lb"], p["ms_lb"]

    bsl, ssl = [], []            # pivot pools (most recent first)
    minor_hi = minor_lo = None
    l_state = s_state = 0
    l_bar = s_bar = -1
    l_sweep_low = s_sweep_high = None
    l_zt = l_zb = s_zt = s_zb = None
    l_vol = s_vol = False

    pos = 0                      # +1 long, -1 short
    entry = stop = tgt = risk = None
    held = 0
    pending = None               # signal fires on close, fills next open
    trades = []
    trades_today = losses_today = 0
    cur_day = None

    def round_levels(px, above):
        g = p["round_grid"]
        base = math.floor(px / g) * g
        return [base + g, base + 2 * g] if above else [base, base - g]

    def sweep_below(i):
        pools = list(ssl)
        if p["use_pdhl"] and d["pdl"][i] is not None:
            pools.append(d["pdl"][i])
        if p["use_round"]:
            pools += round_levels(c[i], False)
        for lvl in pools:
            if l[i] < lvl and c[i] > lvl and (lvl - l[i]) >= d["atr"][i] * p["min_pen"]:
                return lvl
        return None

    def sweep_above(i):
        pools = list(bsl)
        if p["use_pdhl"] and d["pdh"][i] is not None:
            pools.append(d["pdh"][i])
        if p["use_round"]:
            pools += round_levels(c[i], True)
        for lvl in pools:
            if h[i] > lvl and c[i] < lvl and (h[i] - lvl) >= d["atr"][i] * p["min_pen"]:
                return lvl
        return None

    def target_up(i):
        cand = [x for x in bsl if x > c[i]]
        if p["use_pdhl"] and d["pdh"][i] is not None and d["pdh"][i] > c[i]:
            cand.append(d["pdh"][i])
        if p["use_round"]:
            cand += [x for x in round_levels(c[i], True) if x > c[i]]
        return min(cand) if cand else None

    def target_down(i):
        cand = [x for x in ssl if x < c[i]]
        if p["use_pdhl"] and d["pdl"][i] is not None and d["pdl"][i] < c[i]:
            cand.append(d["pdl"][i])
        if p["use_round"]:
            cand += [x for x in round_levels(c[i], False) if x < c[i]]
        return max(cand) if cand else None

    cost = p["fee"] + p["slip"]  # per side, as fraction of price

    for i in range(max(30, lb * 2, 15), n):
        if d["atr"][i] is None or d["rsi"][i] is None or d["vavg"][i] is None:
            continue

        if d["day"][i] != cur_day:
            cur_day = d["day"][i]
            trades_today = losses_today = 0

        # ---- fill pending entry at this bar's open ----
        if pending is not None and pos == 0:
            side, stp, tg = pending
            pos, entry, stop, tgt = side, o[i], stp, tg
            risk = (entry - stop) if side > 0 else (stop - entry)
            held = 0
            pending = None
            if risk <= 0:
                pos = 0  # degenerate, skip

        # ---- manage open position ----
        if pos != 0:
            held += 1
            exit_px = reason = None
            if pos > 0:
                if p["use_be"] and h[i] >= entry + risk * p["be_trig"]:
                    stop = max(stop, entry)
                if p["trail_atr"] > 0 and h[i] >= entry + risk:
                    stop = max(stop, h[i] - d["atr"][i] * p["trail_atr"])
                if l[i] <= stop:
                    exit_px, reason = stop, "stop"
                elif h[i] >= tgt:
                    exit_px, reason = tgt, "target"
            else:
                if p["use_be"] and l[i] <= entry - risk * p["be_trig"]:
                    stop = min(stop, entry)
                if p["trail_atr"] > 0 and l[i] <= entry - risk:
                    stop = min(stop, l[i] + d["atr"][i] * p["trail_atr"])
                if h[i] >= stop:
                    exit_px, reason = stop, "stop"
                elif l[i] <= tgt:
                    exit_px, reason = tgt, "target"
            if exit_px is None and p["scratch_bars"] > 0 and held >= p["scratch_bars"]:
                unreal = (c[i] - entry) / risk if pos > 0 else (entry - c[i]) / risk
                if unreal < p["scratch_r"]:
                    exit_px, reason = c[i], "time"
            if exit_px is None and held >= p["max_hold"]:
                exit_px, reason = c[i], "time"
            if exit_px is not None:
                gross = (exit_px - entry) / entry * pos
                net = gross - 2 * cost
                r_mult = net * entry / risk
                trades.append(dict(i=i, ts=bars[i]["ts"], side=pos, entry=entry,
                                   exit=exit_px, net=net, r=r_mult, held=held, reason=reason))
                if net < 0:
                    losses_today += 1
                pos = 0
                l_state = s_state = 0

        # ---- update confirmed pivots (pivot at i-lb confirms now) ----
        j = i - lb
        if j >= lb:
            if h[j] == max(h[j - lb:j + lb + 1]):
                bsl.insert(0, h[j])
                del bsl[p["max_pools"]:]
            if l[j] == min(l[j - lb:j + lb + 1]):
                ssl.insert(0, l[j])
                del ssl[p["max_pools"]:]
        jm = i - ms
        if jm >= ms:
            if h[jm] == max(h[jm - ms:jm + ms + 1]):
                minor_hi = h[jm]
            if l[jm] == min(l[jm - ms:jm + ms + 1]):
                minor_lo = l[jm]

        # ---- state timeouts ----
        if l_state == 1 and i - l_bar > p["sweep_win"]:
            l_state = 0
        if l_state == 2 and i - l_bar > p["retr_win"]:
            l_state = 0
        if s_state == 1 and i - s_bar > p["sweep_win"]:
            s_state = 0
        if s_state == 2 and i - s_bar > p["retr_win"]:
            s_state = 0

        # ---- stage 1: sweeps ----
        if pos == 0:
            sl_lvl = sweep_below(i)
            if sl_lvl is not None:
                l_state, l_bar, l_sweep_low, s_state = 1, i, l[i], 0
            sh_lvl = sweep_above(i)
            if sh_lvl is not None:
                s_state, s_bar, s_sweep_high, l_state = 1, i, h[i], 0

        # ---- stage 2: displacement + MSS ----
        bull_disp = c[i] > o[i] and (c[i] - o[i]) > d["atr"][i] * p["disp_atr"]
        bear_disp = c[i] < o[i] and (o[i] - c[i]) > d["atr"][i] * p["disp_atr"]
        if l_state == 1 and bull_disp and minor_hi is not None and c[i] > minor_hi:
            l_state, l_bar = 2, i
            l_vol = d["v"][i] > d["vavg"][i] * p["vol_mult"]
            l_zt, l_zb = h[i-1], l[i-1]
        if s_state == 1 and bear_disp and minor_lo is not None and c[i] < minor_lo:
            s_state, s_bar = 2, i
            s_vol = d["v"][i] > d["vavg"][i] * p["vol_mult"]
            s_zt, s_zb = h[i-1], l[i-1]
        # FVG upgrade one bar after displacement
        if l_state == 2 and i == l_bar + 1 and l[i] > h[i-2]:
            l_zt, l_zb = l[i], h[i-2]
        if s_state == 2 and i == s_bar + 1 and h[i] < l[i-2]:
            s_zt, s_zb = l[i-2], h[i]

        # ---- stage 3: entry ----
        if pos != 0 or pending is not None:
            continue
        can_trade = trades_today < p["max_daily"] and losses_today < p["max_loss"]
        regime_ok = (not p["use_regime"] or (d["atrpct_med"][i] is not None
                     and d["atr"][i] / c[i] >= d["atrpct_med"][i] * p["regime_mult"]))
        kz_ok = (not p["use_kz"]) or any(a <= d["hour"][i] < b for a, b in KILLZONES)
        htf = d["htf_ema"][i]

        rng = h[i] - l[i]
        close_pos = (c[i] - l[i]) / rng if rng > 0 else 0.5
        long_trigger = (p["entry_mode"] == "momentum"
                        and l_state == 2 and i == l_bar) or \
                       (p["entry_mode"] == "sweep"
                        and l_state == 1 and i == l_bar and close_pos >= p["reclaim_pos"]) or \
                       (p["entry_mode"] == "retrace"
                        and l_state == 2 and i > l_bar and l[i] <= l_zt and c[i] >= l_zb
                        and (not p["confirm_close"] or c[i] > o[i]))
        if long_trigger and p["side"] != "short":
            if p["entry_mode"] == "sweep":
                l_vol = d["v"][i] > d["vavg"][i] * p["vol_mult"]
            stp = (min(l_sweep_low, l_zb) if l_zb is not None else l_sweep_low) - d["atr"][i] * p["stop_buf"]
            if p["target_mode"] == "vwap" and d["vwap"][i] > c[i]:
                tg = d["vwap"][i]
            else:
                tg = target_up(i)
            if tg is not None and p["max_tgt_atr"] > 0 and (tg - c[i]) > d["atr"][i] * p["max_tgt_atr"]:
                tg = c[i] + d["atr"][i] * p["max_tgt_atr"] if p["tp_fallback"] else None
            vwap_ok = (p["use_vwap"] == 0 or
                       (p["use_vwap"] == 1 and c[i] > d["vwap"][i]) or
                       (p["use_vwap"] == 2 and c[i] < d["vwap"][i]))
            ok = (tg is not None and c[i] > stp
                  and (tg - c[i]) / (c[i] - stp) >= p["rr_min"]
                  and vwap_ok
                  and d["rsi"][i] < p["rsi_hi"]
                  and l_vol and (not p["use_htf"] or (htf is not None and c[i] > htf))
                  and regime_ok and kz_ok and can_trade)
            if ok:
                pending = (1, stp, tg)
                trades_today += 1
                l_state = 0

        short_trigger = (p["entry_mode"] == "momentum"
                         and s_state == 2 and i == s_bar) or \
                        (p["entry_mode"] == "sweep"
                         and s_state == 1 and i == s_bar and close_pos <= 1 - p["reclaim_pos"]) or \
                        (p["entry_mode"] == "retrace"
                         and s_state == 2 and i > s_bar and h[i] >= s_zb and c[i] <= s_zt
                         and (not p["confirm_close"] or c[i] < o[i]))
        if short_trigger and p["side"] != "long":
            if p["entry_mode"] == "sweep":
                s_vol = d["v"][i] > d["vavg"][i] * p["vol_mult"]
            stp = (max(s_sweep_high, s_zt) if s_zt is not None else s_sweep_high) + d["atr"][i] * p["stop_buf"]
            if p["target_mode"] == "vwap" and d["vwap"][i] < c[i]:
                tg = d["vwap"][i]
            else:
                tg = target_down(i)
            if tg is not None and p["max_tgt_atr"] > 0 and (c[i] - tg) > d["atr"][i] * p["max_tgt_atr"]:
                tg = c[i] - d["atr"][i] * p["max_tgt_atr"] if p["tp_fallback"] else None
            vwap_ok = (p["use_vwap"] == 0 or
                       (p["use_vwap"] == 1 and c[i] < d["vwap"][i]) or
                       (p["use_vwap"] == 2 and c[i] > d["vwap"][i]))
            ok = (tg is not None and c[i] < stp
                  and (c[i] - tg) / (stp - c[i]) >= p["rr_min"]
                  and vwap_ok
                  and d["rsi"][i] > p["rsi_lo"]
                  and s_vol and (not p["use_htf"] or (htf is not None and c[i] < htf))
                  and regime_ok and kz_ok and can_trade)
            if ok:
                pending = (-1, stp, tg)
                trades_today += 1
                s_state = 0

    return summarize(trades, collect_trades)


def summarize(trades, collect):
    if not trades:
        return dict(trades=0)
    wins = [t for t in trades if t["net"] > 0]
    losses = [t for t in trades if t["net"] <= 0]
    gw = sum(t["net"] for t in wins)
    gl = -sum(t["net"] for t in losses)
    total_r = sum(t["r"] for t in trades)
    # equity curve on net returns (compounded, full notional per trade)
    eq, peak, mdd = 1.0, 1.0, 0.0
    for t in trades:
        eq *= (1 + t["net"])
        peak = max(peak, eq)
        mdd = max(mdd, 1 - eq / peak)
    out = dict(
        trades=len(trades),
        win_rate=round(100 * len(wins) / len(trades), 1),
        profit_factor=round(gw / gl, 2) if gl > 0 else float("inf"),
        total_return_pct=round((eq - 1) * 100, 2),
        avg_r=round(total_r / len(trades), 3),
        total_r=round(total_r, 1),
        max_dd_pct=round(mdd * 100, 2),
        avg_hold=round(sum(t["held"] for t in trades) / len(trades), 1),
        by_exit={r: sum(1 for t in trades if t["reason"] == r) for r in ("target", "stop", "time")},
    )
    if collect:
        out["trade_list"] = trades
    return out


def fmt(res):
    if res["trades"] == 0:
        return "no trades"
    return (f"trades={res['trades']:3d}  win={res['win_rate']:5.1f}%  PF={res['profit_factor']:5.2f}  "
            f"ret={res['total_return_pct']:+7.2f}%  avgR={res['avg_r']:+.3f}  totR={res['total_r']:+6.1f}  "
            f"DD={res['max_dd_pct']:5.2f}%  hold={res['avg_hold']:.1f}b  {res['by_exit']}")


if __name__ == "__main__":
    args = sys.argv[1:]
    use15 = any(a == "data=15m" for a in args)
    args = [a for a in args if not a.startswith("data=")]
    bars = load(DATA_15 if use15 else DATA)
    if use15:
        DEFAULTS["bar_min"] = 15
        DEFAULTS["max_hold"] = 2
    if "--sweep" in args:
        base = dict(DEFAULTS)
        print(f"BASE: {fmt(run(bars, base))}\n")
        grids = dict(
            min_pen=[0.05, 0.15, 0.30, 0.50],
            reclaim_pos=[0.4, 0.5, 0.65, 0.8],
            rr_min=[0.8, 1.0, 1.3, 1.6],
            vol_mult=[0.8, 1.0, 1.2, 1.5],
            be_trig=[0.5, 0.75, 1.0, 1.5],
            use_be=[0, 1],
            stop_buf=[0.75, 1.0, 1.5, 2.0],
            max_hold=[4, 6, 9, 12],
            max_tgt_atr=[1.5, 2.0, 2.5, 3.5],
            scratch_bars=[0, 2, 3, 4],
            use_regime=[0, 1],
            regime_mult=[0.8, 1.0, 1.3],
            use_kz=[0, 1],
            use_round=[0, 1],
            use_pdhl=[0, 1],
            use_htf=[0, 1],
            use_vwap=[0, 1],
            liq_lb=[10, 15, 20, 30],
            max_daily=[3, 5, 8],
            rsi_hi=[60.0, 65.0, 70.0],
            rsi_lo=[30.0, 35.0, 40.0],
        )
        for key, vals in grids.items():
            for val in vals:
                p = dict(base); p[key] = val
                tag = "*" if val == base[key] else " "
                print(f"{tag}{key}={val:<6} {fmt(run(bars, p))}")
            print()
    else:
        p = dict(DEFAULTS)
        for a in args:
            if "=" in a:
                k, v = a.split("=", 1)
                p[k] = type(DEFAULTS[k])(float(v)) if isinstance(DEFAULTS[k], (int, float)) else v
        res = run(bars, p, collect_trades=True)
        print(fmt(res))
        for t in res.get("trade_list", [])[-15:]:
            dt = datetime.fromtimestamp(t["ts"], tz=timezone.utc).strftime("%m-%d %H:%M")
            print(f"  {dt}  {'LONG ' if t['side']>0 else 'SHORT'}  entry={t['entry']:.1f}  "
                  f"exit={t['exit']:.1f}  R={t['r']:+.2f}  {t['held']}b  {t['reason']}")
