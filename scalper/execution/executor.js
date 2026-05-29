import { appendFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { CONFIG } from '../config.js';
import * as polymarket from '../feeds/polymarket.js';

const LOG_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'logs');

function ensureLogDir() {
  try { mkdirSync(LOG_DIR, { recursive: true }); } catch {}
}

function logEvent(obj) {
  const date = new Date().toISOString().slice(0, 10);
  const line = JSON.stringify({ ...obj, _ts: Date.now() }) + '\n';
  try {
    ensureLogDir();
    appendFileSync(join(LOG_DIR, `${date}.jsonl`), line);
  } catch {}
}

let _tradeSeq = 0;

class Executor {
  constructor(risk, forceGraph) {
    this.risk  = risk;
    this.fg    = forceGraph;
  }

  async execute(edge, signal) {
    const t0 = performance.now();

    // ── Pre-flight checks (all in-memory, zero latency) ──────────────
    const guard = this.risk.canTrade();
    if (!guard.ok) {
      logEvent({ type: 'skip', reason: guard.reason, edge_lag: edge.lag_pct });
      return { skipped: true, reason: guard.reason };
    }

    if (!signal.direction) {
      logEvent({ type: 'skip', reason: 'no_signal', conflicts: signal.conflicts });
      return { skipped: true, reason: 'no signal direction' };
    }

    if (signal.confidence < (CONFIG.MIN_CONFIDENCE ?? 0.5)) {
      logEvent({ type: 'skip', reason: 'low_confidence', confidence: signal.confidence });
      return { skipped: true, reason: 'low confidence' };
    }

    if (signal.conflicts.length > 0 && signal.confidence < 0.7) {
      logEvent({ type: 'skip', reason: 'conflicts', conflicts: signal.conflicts });
      return { skipped: true, reason: 'signal conflicts' };
    }

    // ── Direction sanity: signal and edge must agree ──────────────────
    if (signal.direction !== edge.direction) {
      logEvent({ type: 'skip', reason: 'direction_mismatch', edge: edge.direction, signal: signal.direction });
      return { skipped: true, reason: 'signal/edge direction mismatch' };
    }

    // ── Position sizing ───────────────────────────────────────────────
    const entryPrice = edge.direction === 'UP'
      ? (polymarket.getState().up.bestAsk ?? edge.impliedProb)
      : (polymarket.getState().down.bestAsk ?? (1 - edge.impliedProb));

    const { shares, cost_usdc: costUsdc, max_loss: maxLoss } = this.risk.sizePosition(entryPrice, signal.confidence);

    const tradeId = `trade_${Date.now()}_${++_tradeSeq}`;

    logEvent({
      type: 'edge',
      lag_pct: edge.lag_pct,
      direction: edge.direction,
      liquidity: edge.liquidity,
      momentum_prob: edge.momentumProb,
      implied_prob: edge.impliedProb,
    });

    logEvent({
      type: 'signal',
      direction: signal.direction,
      confidence: signal.confidence,
      conflicts: signal.conflicts,
      votes: signal.votes?.map(v => `${v.dir}@${v.weight}:${v.source}`),
    });

    // ── Execute ───────────────────────────────────────────────────────
    if (CONFIG.PAPER_TRADE) {
      const record = this.risk.recordPaperTrade({
        direction: edge.direction,
        entryPrice,
        shares,
        costUsdc,
        latencyMs: performance.now() - t0,
        edge,
        signal,
      });

      logEvent({
        type: 'trade',
        id: tradeId,
        paper: true,
        direction: edge.direction,
        entry_price: entryPrice,
        shares,
        cost_usdc: costUsdc,
        latency_ms: record.latencyMs,
      });

      return { tradeId, paper: true, record, latency_ms: record.latencyMs };
    }

    // ── Live order submission ─────────────────────────────────────────
    let resp;
    try {
      resp = await polymarket.submitOrder({
        direction: edge.direction,
        sizeUsdc:  costUsdc,
        price:     entryPrice,
      });
    } catch (err) {
      logEvent({ type: 'error', stage: 'order_submit', message: err.message });
      return { error: err.message };
    }

    const latency = performance.now() - t0;

    if (latency > CONFIG.EXEC_DEADLINE_MS) {
      logEvent({ type: 'warn', message: `slow_exec ${latency.toFixed(0)}ms`, tradeId });
    }

    const pos = this.risk.openPosition({
      id: tradeId,
      direction: edge.direction,
      entryPrice,
      shares,
      costUsdc,
    });

    logEvent({
      type: 'trade',
      id: tradeId,
      paper: false,
      direction: edge.direction,
      entry_price: entryPrice,
      shares,
      cost_usdc: costUsdc,
      latency_ms: latency,
      order_resp: resp,
    });

    return { tradeId, resp, pos, latency_ms: latency };
  }

  recordOutcome(tradeId, exitPrice, reason = 'expiry') {
    const record = this.risk.closePosition(tradeId, exitPrice, reason);
    if (!record) return null;

    logEvent({
      type: 'outcome',
      id: tradeId,
      exit_price: exitPrice,
      pnl: record.pnl,
      reason,
    });

    // Reinforce / dampen force graph weights
    this.fg?.updateWeights({ pnl: record.pnl });

    return record;
  }
}

export { Executor, logEvent };
