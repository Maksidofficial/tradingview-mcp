---
name: scalp-bot
description: Run the Liquidity Pool Scalp Bot — detect BSL/SSL sweep setups on futures, execute entries in replay mode or set live alerts. Use when the user wants to scalp futures using a liquidity-to-liquidity methodology on a 15-30 minute hold window.
---

# Liquidity Pool Scalp Bot (v3, BTC-tuned)

You are executing a liquidity-to-liquidity scalp strategy. Two entry modes:

- **Sweep Reclaim (default, backtested best)** — enter on the bar that wicks through a
  liquidity pool (swing high/low, PDH/PDL, or round number) and closes back inside with
  strength. Fast: zero confirmation lag.
- **Retrace (conservative)** — wait for displacement + structure shift, then enter on the
  pullback into the FVG/OB zone. More confirmation, more lag.

Hold window: up to 9 bars on 5m (45 min; set Max Bars to 6 for a strict 30-min window).
Stop: 0.75 ATR beyond the sweep wick. Target: nearest opposing pool, capped at 3.5 ATR.
Breakeven at +1R. Daily governor: max 3 trades, hard stop after 2 losses.

## ⚠️ Backtest Findings (read before trading live)

Validated against 30 days of real BTCUSDT-perp 5m data (`backtest/backtest_scalp.py`):

1. **The raw edge is thin — roughly breakeven before costs.** Best config reached
   profit factor ~0.9-1.0 with maker fees. This is NOT a money printer; treat it as a
   framework for discretionary confirmation, not blind automation.
2. **Costs decide everything.** Taker fees (0.05%/side) cost ~0.4R per trade at scalp
   stop distances. Use limit/maker orders or don't trade this at all.
3. **Tight stops fail.** Wick + 0.25 ATR stops got chewed by 5m noise (win rate 23%).
   Wick + 0.75 ATR lifted win rate to ~45%.
4. **VWAP/HTF trend filters HURT this setup** (PF dropped to 0.2-0.4 when enabled).
   A sweep-reversal long happens at the lows — requiring price above VWAP contradicts
   the setup. They are off by default; the dashboard still shows them as context.
5. **Targets must be reachable.** Pool targets further than ~3.5 ATR can't be hit
   within a 30-45 min hold; the strategy caps them.
6. To re-validate on fresh data: `python3 backtest/fetch_okx.py 30 5m && python3 backtest/backtest_scalp.py`

---

## Phase 1 — Chart Setup (once per session)

1. `chart_set_symbol` — set the futures symbol (e.g., "NQ1!", "ES1!", "MNQ1!")
2. `chart_set_timeframe` → "15" — establish HTF context first
3. `capture_screenshot` — note dominant trend and major liquidity zones
4. `chart_set_timeframe` → "5" — switch to execution timeframe

Load the strategy:
5. `pine_new` → create blank strategy
6. `pine_set_source` — inject the full contents of `pine/scalp_liquidity_bot.pine`
7. `pine_smart_compile` — compile and add to chart
8. `pine_get_errors` — confirm 0 errors before continuing

If errors appear: `pine_get_console` for details, fix inputs, retry compile.

---

## Phase 2 — HTF Context Read (15m)

Switch to 15m temporarily:
1. `chart_set_timeframe` → "15"
2. `data_get_pine_lines` with `study_filter: "Liquidity Scalp"` — read BSL/SSL levels
3. `data_get_study_values` — note RSI and VWAP bias at the higher timeframe
4. `data_get_ohlcv` with `summary: true, count: 20` — recent price action context
5. Record: dominant bias (bullish/bearish), key BSL level, key SSL level
6. `chart_set_timeframe` → "5" — return to execution timeframe

---

## Phase 3 — Signal Check (repeat every bar or on demand)

Read the dashboard:
1. `data_get_pine_tables` with `study_filter: "Liquidity Scalp"` — get all table cells

Key dashboard rows:
- **MODE**: `SWEEP RECLAIM` or `RETRACE`
- **SIGNAL**: `NONE`, `SSL SWEPT` / `BSL SWEPT` (sweep on current bar), `LONG/SHORT ARMED`
  (retrace mode zone active), or `LONG ▲` / `SHORT ▼` (entry firing now)
- **BSL / SSL / PDH / PDL / ROUND**: all tracked liquidity pool levels
- **RSI / VOLUME / SESSION**: filter status
- **TRADES TODAY**: count vs limit and losses — if at limit, no more trades

Interpretation:
- In Sweep Reclaim mode the sweep bar IS the entry bar — signals appear and fire on the same candle
- In Retrace mode: `SWEPT` → displacement arms a zone box → entry fires on the pullback into it
- Entry triangle + label with E/SL/TP appear when the trade fires

Read exact entry levels:
2. `data_get_pine_labels` with `study_filter: "Liquidity Scalp"` — get entry label with E/SL/TP values

---

## Phase 4 — Entry Execution (Replay Mode)

When SIGNAL = `LONG ▲` or `SHORT ▼` with CONFLUENCE = 5:

1. `replay_start` with today's date — enter replay mode
2. `replay_step` — advance to the signal bar
3. `quote_get` — confirm current price matches entry level from label
4. `replay_trade` with action `"buy"` (long) or `"sell"` (short)
5. `replay_status` — confirm position opened, note entry price

Draw reference lines:
6. `draw_shape` — horizontal_line at stop loss price (red)
7. `draw_shape` — horizontal_line at target price (green)
8. `draw_shape` — text at entry bar: "Entry: [price] | SL: [sl] | TP: [tp]"
9. `capture_screenshot` — document the entry setup

---

## Phase 5 — Position Management

After entry, advance bars and monitor:

1. `replay_step` — advance one bar
2. `replay_status` — check: `position`, `realized_pnl`, `current_date`
3. `data_get_pine_tables` with `study_filter: "Liquidity Scalp"` — read POSITION cell (shows bars held)

**Exit triggers (check in order):**
- If POSITION cell shows `FLAT` → stop or target was hit automatically → go to Phase 6
- If bars_held ≥ 6 (max hold reached) → `replay_trade` with action `"close"` → Phase 6
- If price reaches within 0.1% of target → `replay_trade` with action `"close"` → Phase 6
- If against position by > 50% of original risk → consider early exit

Repeat steps 1-3 until exit triggers.

---

## Phase 6 — Trade Review

1. `replay_status` — capture final P&L
2. `draw_clear` — remove reference lines
3. `capture_screenshot` — full chart showing entry → exit with levels
4. `replay_stop` — return to realtime

Report the following for each completed trade:
```
Symbol:      [symbol]
Direction:   Long / Short
Entry:       [price]
Exit:        [price]  (stop / target / time / manual)
Stop:        [price]
Target:      [price]
R:R Planned: [x.x]:1
R:R Achieved:[x.x]:1
Bars Held:   [n]  (~[n×5] min)
P&L:         +/- [amount]
Confluence:  [score]/5
```

---

## Phase 7 — Live Mode (Alerts, No Replay)

For monitoring a live chart without replay:

1. Complete Phases 1-3 above to load strategy and check signal
2. When SIGNAL first appears: `alert_create` at the entry price
3. `alert_create` at the stop loss price (condition: "less_than" for longs, "greater_than" for shorts)
4. `alert_create` at the target price (condition: "greater_than" for longs, "less_than" for shorts)
5. `capture_screenshot` — document the setup

To monitor continuously:
- Call `data_get_pine_tables` with `study_filter: "Liquidity Scalp"` periodically
- When SIGNAL changes from `NONE` to `LONG/SHORT` → execute steps 2-5 above
- When position closes → `alert_delete` all pending alerts for this setup

---

## Key Rules

| Rule | Guideline |
|------|-----------|
| Entry (default mode) | The sweep-reclaim bar itself — wick through pool, strong close back inside |
| Reclaim strength | Close must be in the upper 50% of the bar range (lower 50% for shorts) |
| Order type | **Maker/limit orders only** — taker fees erase the edge (backtested) |
| Trend filters | OFF — VWAP/HTF gating hurts sweep reversals (backtested); use as context only |
| Max hold | 9 bars (45 min on 5m); set 6 for a strict 30-min window |
| Min R:R | 1:1 against the capped target (wide stops make 2:1 unreachable intraday) |
| Stop placement | Beyond the sweep wick + 0.75 ATR buffer — tight stops get chewed |
| Breakeven | Stop auto-moves to entry once trade runs +1R |
| Target | Nearest opposite pool (swing/PDH/PDL/round number), capped at 3.5 ATR |
| Max daily trades | 3 — enforced by the strategy itself |
| After 2 losers | Strategy hard-stops for the day — do not override |

---

## Troubleshooting

**No signals appearing:**
- Check `in_session` is `ACTIVE ✓` in dashboard
- Verify volume is adequate (`data_get_study_values` for volume)
- Try increasing `Pivot Lookback` input to find more liquidity pools
- Use 1m or 3m chart for lower-volatility instruments

**Strategy not compiling:**
- `pine_get_errors` to see exact error lines
- `pine_get_console` for compile log
- Common fix: ensure timeframe matches session timezone inputs

**No BSL/SSL showing:**
- The pivot lookback may be too large for current bar count
- Try `liq_lb = 10` instead of 15
- Scroll chart back further to give more historical bars

**VWAP shows wrong bias:**
- VWAP resets daily — check that chart has today's session data loaded
- Use `chart_scroll_to_date` to ensure current session is visible
