---
name: scalp-bot
description: Run the Liquidity Pool Scalp Bot — detect BSL/SSL sweep setups on futures, execute entries in replay mode or set live alerts. Use when the user wants to scalp futures using a liquidity-to-liquidity methodology on a 15-30 minute hold window.
---

# Liquidity Pool Scalp Bot

You are executing a liquidity-to-liquidity scalp strategy on futures. The edge is:
**sweep a liquidity pool → displacement → enter at FVG/OB → target the next pool**.

Hold window: 3-6 bars on the 5m chart (15-30 minutes).

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

Look for in the dashboard output:
- **SIGNAL** cell: `LONG ▲`, `SHORT ▼`, `WATCH ▲/▼`, or `NONE`
- **CONFLUENCE**: score out of 5 (need ≥ 5 for a full entry, ≥ 3 for a watch)
- **BSL / SSL**: nearest pool levels
- **VWAP**: direction bias
- **SESSION**: must be `ACTIVE ✓`

If SIGNAL shows `NONE` or CONFLUENCE < 3 — no trade. Advance bars and recheck.

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
| Minimum confluence | 5/5 for entry, 3/5 for "watch" |
| Session filter | London (02:00-11:00 UTC) or NY (08:30-16:00 ET) only |
| Max hold | 6 bars (30 min on 5m) — close on time if not stopped/targeted |
| Min R:R | 2:1 — the strategy only fires entries when this is met |
| Stop placement | Beyond the swept liquidity level + 0.1% buffer |
| Target | Nearest opposite liquidity pool |
| Max daily trades | 3 — stop after 3 regardless of outcome |
| After 2 losers | Stop for the session — do not revenge trade |

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
