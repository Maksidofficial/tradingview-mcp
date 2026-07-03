#!/usr/bin/env python3
"""Fetch historical 5m candles for BTC-USDT-SWAP from OKX public API.

Usage: python3 backtest/fetch_okx.py [days] [bar] [instId]
Writes CSV to backtest/data/<instId>_<bar>.csv (oldest first):
  ts_ms,open,high,low,close,volume
"""
import json
import os
import sys
import time
import urllib.request

DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
BAR = sys.argv[2] if len(sys.argv) > 2 else "5m"
INST = sys.argv[3] if len(sys.argv) > 3 else "BTC-USDT-SWAP"

BASE = "https://www.okx.com/api/v5/market/history-candles"
LIMIT = 100  # history-candles max per request

bar_minutes = {"1m": 1, "3m": 3, "5m": 5, "15m": 15, "30m": 30, "1H": 60}[BAR]
target_bars = DAYS * 24 * 60 // bar_minutes

rows = {}  # ts -> row, dedup
after = ""  # fetch records older than this ts

while len(rows) < target_bars:
    url = f"{BASE}?instId={INST}&bar={BAR}&limit={LIMIT}"
    if after:
        url += f"&after={after}"
    req = urllib.request.Request(url, headers={"User-Agent": "backtest/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read())
    if payload.get("code") != "0":
        print("API error:", payload, file=sys.stderr)
        sys.exit(1)
    data = payload["data"]  # newest first
    if not data:
        break
    for r in data:
        ts = int(r[0])
        rows[ts] = (ts, float(r[1]), float(r[2]), float(r[3]), float(r[4]), float(r[5]))
    after = data[-1][0]  # oldest ts in this page
    if len(rows) % 2000 < LIMIT:
        print(f"  {len(rows)}/{target_bars} bars...", file=sys.stderr)
    time.sleep(0.15)  # rate limit: 20 req/2s allowed, stay well under

ordered = [rows[k] for k in sorted(rows)]
os.makedirs(os.path.join(os.path.dirname(__file__), "data"), exist_ok=True)
out = os.path.join(os.path.dirname(__file__), "data", f"{INST}_{BAR}.csv")
with open(out, "w") as f:
    f.write("ts_ms,open,high,low,close,volume\n")
    for r in ordered:
        f.write(",".join(str(x) for x in r) + "\n")
print(f"Wrote {len(ordered)} bars -> {out}")
print(f"Range: {time.strftime('%Y-%m-%d %H:%M', time.gmtime(ordered[0][0]/1000))} .. "
      f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(ordered[-1][0]/1000))} UTC")
