import { CONFIG } from '../config.js';

// ── Risk manager — all state resets at midnight UTC ─────────────────────────

class RiskManager {
  constructor() {
    this._resetDay();
    this._scheduleReset();
  }

  _resetDay() {
    this.dailyPnL       = 0;     // realised P&L today (USDC)
    this.dailyExposure  = 0;     // total notional opened today (USDC)
    this.openPositions  = [];    // { id, direction, entryPrice, size, entryTs, maxLoss }
    this.tradesLog      = [];    // all completed trades
    this._day = new Date().toISOString().slice(0, 10);
  }

  _scheduleReset() {
    const now   = new Date();
    const nextMidnight = new Date(now);
    nextMidnight.setUTCHours(24, 0, 0, 0);
    setTimeout(() => {
      this._resetDay();
      this._scheduleReset();
    }, nextMidnight - now);
  }

  // ── Guards ─────────────────────────────────────────────────────────

  canTrade() {
    const capital = CONFIG.CAPITAL_USDC;

    if (this.dailyExposure >= capital * CONFIG.DAILY_CAP_PCT) {
      return { ok: false, reason: `daily exposure cap hit (${this.dailyExposure.toFixed(2)} USDC)` };
    }

    if (this.dailyPnL <= -capital * CONFIG.DAILY_CAP_PCT) {
      return { ok: false, reason: `daily loss cap hit (${this.dailyPnL.toFixed(2)} USDC)` };
    }

    return { ok: true };
  }

  /**
   * Size a position.
   * For binary Polymarket contracts priced at `price` (0→1 USDC per share):
   * max_loss = shares × price  (if contract expires worthless)
   * → shares = risk_usdc / price
   * Higher price → fewer shares (cost is always = risk_usdc).
   */
  sizePosition(entryPrice, confidence = 1) {
    const capital  = CONFIG.CAPITAL_USDC;
    const riskUsdc = capital * CONFIG.PER_TRADE_RISK_PCT;  // 0.5% of capital

    const price  = Math.max(0.01, Math.min(0.99, entryPrice));
    const shares = riskUsdc / price;
    const cost   = shares * price;  // always equals riskUsdc

    return {
      shares,
      cost_usdc:  cost,
      max_loss:   riskUsdc,
    };
  }

  // ── Open / close positions ─────────────────────────────────────────

  openPosition({ id, direction, entryPrice, shares, costUsdc }) {
    const pos = {
      id,
      direction,
      entryPrice,
      shares,
      costUsdc,
      entryTs: Date.now(),
      maxLoss: costUsdc,   // worst case: contract expires worthless
    };
    this.openPositions.push(pos);
    this.dailyExposure += costUsdc;
    return pos;
  }

  closePosition(id, exitPrice, reason = 'manual') {
    const idx = this.openPositions.findIndex(p => p.id === id);
    if (idx === -1) return null;
    const [pos] = this.openPositions.splice(idx, 1);

    const pnl = (exitPrice - pos.entryPrice) * pos.shares;
    this.dailyPnL += pnl;

    const record = { ...pos, exitPrice, exitTs: Date.now(), pnl, reason };
    this.tradesLog.push(record);
    return record;
  }

  // Check all open positions for hard-stop breach
  checkHardStops(currentPrices = {}) {
    const closed = [];
    for (const pos of [...this.openPositions]) {
      const cur = currentPrices[pos.direction === 'UP' ? 'up' : 'down'] ?? pos.entryPrice;
      const unrealisedPct = (cur - pos.entryPrice) / pos.entryPrice;
      if (unrealisedPct <= -CONFIG.HARD_STOP_PCT) {
        const record = this.closePosition(pos.id, cur, 'hard_stop');
        if (record) closed.push(record);
      }
    }
    return closed;
  }

  // Paper trade recording (no real position, just log)
  recordPaperTrade({ direction, entryPrice, shares, costUsdc, latencyMs, edge, signal }) {
    const id = `paper_${Date.now()}`;
    const record = {
      id, direction, entryPrice, shares, costUsdc, latencyMs,
      ts: Date.now(), paper: true,
      edge_lag: edge?.lag_pct,
      confidence: signal?.confidence,
    };
    this.tradesLog.push(record);
    this.dailyExposure += costUsdc;
    return record;
  }

  stats() {
    return {
      dailyPnL:      this.dailyPnL,
      dailyExposure: this.dailyExposure,
      dailyCapUsed:  this.dailyExposure / (CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT),
      openCount:     this.openPositions.length,
      totalTrades:   this.tradesLog.length,
      capital:       CONFIG.CAPITAL_USDC,
    };
  }
}

export { RiskManager };
