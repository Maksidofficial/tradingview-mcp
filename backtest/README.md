# Offline Backtester

Validates the Liquidity Scalp Bot against real BTCUSDT perpetual data from OKX
(no API key needed) — useful because the Pine strategy can't be compiled/tested
without a live TradingView Desktop session.

## Usage

```bash
# 1. Fetch data (30 days of 5m candles)
python3 backtest/fetch_okx.py 30 5m

# 2. Run with shipped defaults (mirrors pine/scalp_liquidity_bot.pine v3)
python3 backtest/backtest_scalp.py

# 3. Override any parameter
python3 backtest/backtest_scalp.py entry_mode=retrace rr_min=1.5 use_kz=1

# 4. One-at-a-time parameter sweep around the defaults
python3 backtest/backtest_scalp.py --sweep

# 5. 15m timeframe (fetch first: python3 backtest/fetch_okx.py 60 15m)
python3 backtest/backtest_scalp.py data=15m
```

## Key findings (BTCUSDT-perp 5m, Jun 2026, 30 days)

| Config | Trades | Win | PF | Return |
|--------|--------|-----|-----|--------|
| v2 defaults (retrace, tight stops, trend filters) | 0-58 | 13-26% | 0.04-0.16 | -5 to -9% |
| v3 defaults, maker fees (0.02%) | 81 | 43% | 0.94 | -0.7% |
| v3 defaults, zero fees | 82 | 45% | 1.31 | +2.9% |

- The raw signal edge is thin and positive only before costs — trade maker-only
- Stops: wick + 0.75 ATR >> wick + 0.25 ATR (win rate 45% vs 23%)
- VWAP / HTF trend filters actively hurt sweep-reversal entries
- Pool targets must be capped at ~3.5 ATR to be reachable in a 30-45 min hold
- Fee sensitivity: taker fees (0.05%/side) cost ~0.4R per trade at scalp distances

No lookahead: pivots only count after confirmation, HTF EMA uses completed bars,
PDH/PDL from the prior completed UTC day. Entries fill at next-bar open;
stop is assumed hit before target when both are within one bar (pessimistic).
