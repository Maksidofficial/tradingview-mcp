import { CONFIG } from '../config.js';

// ── Signal aggregation ────────────────────────────────────────────────────────

/**
 * Aggregate all feed signals into a single directional verdict.
 *
 * @param {object} feeds  - { binance, tradingview, cryptoquant, polymarket, forceGraph }
 * @returns {{ direction: 'UP'|'DOWN'|null, confidence: number, conflicts: string[] }}
 */
function aggregate(feeds) {
  const { binance: b, tradingview: tv, cryptoquant: cq, polymarket: pm, forceGraph: fg } = feeds;

  const votes = [];  // { dir: 'UP'|'DOWN', weight: number, source: string }

  // ── Force graph cluster (weight 0.35) ─────────────────────────────
  if (fg && fg.convergence > 0.6) {
    votes.push({
      dir:    fg.bias === 'BULL' ? 'UP' : 'DOWN',
      weight: 0.35,
      source: `forceGraph(conv=${fg.convergence.toFixed(2)})`,
    });
  }

  // ── TradingView RSI (weight 0.20) ─────────────────────────────────
  if (tv?.rsi != null) {
    if (tv.rsi < 30) votes.push({ dir: 'UP',   weight: 0.20, source: `rsi(${tv.rsi.toFixed(1)})` });
    if (tv.rsi > 70) votes.push({ dir: 'DOWN', weight: 0.20, source: `rsi(${tv.rsi.toFixed(1)})` });
  }

  // ── TradingView MACD histogram cross (weight 0.15) ────────────────
  if (tv?.macdHist != null) {
    const dir = tv.macdHist > 0 ? 'UP' : 'DOWN';
    votes.push({ dir, weight: 0.15, source: `macd(${tv.macdHist.toFixed(2)})` });
  }

  // ── TradingView EMA cross (weight 0.10) ───────────────────────────
  if (tv?.ema9 != null && tv?.ema21 != null) {
    const dir = tv.ema9 > tv.ema21 ? 'UP' : 'DOWN';
    votes.push({ dir, weight: 0.10, source: `emaCross` });
  }

  // ── CryptoQuant net flow (weight 0.15) ────────────────────────────
  // Net outflow (positive) = bullish; large inflow (negative) = bearish
  if (cq?.netFlow != null) {
    if (cq.netFlow > 200) {
      votes.push({ dir: 'UP',   weight: 0.15, source: `cqFlow(+${cq.netFlow.toFixed(0)})` });
    } else if (cq.netFlow < -200) {
      votes.push({ dir: 'DOWN', weight: 0.15, source: `cqFlow(${cq.netFlow.toFixed(0)})` });
    }
  }

  // ── Binance 5m kline momentum (weight 0.15) ───────────────────────
  const kline = b?.kline;
  if (kline && kline.open !== kline.close) {
    const klineMove = (kline.close - kline.open) / kline.open;
    if (Math.abs(klineMove) > 0.001) {
      const dir = klineMove > 0 ? 'UP' : 'DOWN';
      votes.push({ dir, weight: 0.15, source: `kline(${(klineMove * 100).toFixed(2)}%)` });
    }
  }

  // ── Binance short-term momentum (weight 0.10) ────────────────────
  const price    = b?.price;
  const price10s = b?.price_10s;
  if (price && price10s) {
    const move = (price - price10s) / price10s;
    if (Math.abs(move) > 0.0005) {
      votes.push({ dir: move > 0 ? 'UP' : 'DOWN', weight: 0.10, source: `spot10s(${(move * 100).toFixed(3)}%)` });
    }
  }

  // ── Polymarket imbalance (weight 0.10) ───────────────────────────
  const upMid   = pm?.up?.mid;
  const downMid = pm?.down?.mid;
  if (upMid != null && downMid != null) {
    const imb = upMid - downMid;
    if (Math.abs(imb) > 0.05) {
      votes.push({ dir: imb > 0 ? 'UP' : 'DOWN', weight: 0.10, source: `pmImbalance(${imb.toFixed(3)})` });
    }
  }

  if (votes.length === 0) return { direction: null, confidence: 0, conflicts: [] };

  // ── Weighted vote tallying ─────────────────────────────────────────
  let upWeight = 0, downWeight = 0;
  for (const v of votes) {
    if (v.dir === 'UP')   upWeight   += v.weight;
    else                  downWeight += v.weight;
  }

  const totalWeight = upWeight + downWeight;
  const direction = upWeight >= downWeight ? 'UP' : 'DOWN';
  const winnerW   = direction === 'UP' ? upWeight : downWeight;
  const loserW    = totalWeight - winnerW;

  // Conflict: sources that voted for the losing side
  const conflicts = votes
    .filter(v => v.dir !== direction)
    .map(v => v.source);

  const conflictScore = totalWeight > 0 ? loserW / totalWeight : 0;

  // Confidence: winner share × vote density bonus
  const voteDensity = Math.min(1, votes.length / 5);
  const confidence  = Math.min(1, (winnerW / Math.max(totalWeight, 0.01)) * 0.7 + voteDensity * 0.3);

  // Suppress if conflict too high
  if (conflictScore > (CONFIG.SIGNAL_CONFLICT_MAX ?? 0.4)) {
    return { direction: null, confidence, conflicts, conflictScore, votes };
  }

  return { direction, confidence, conflicts, conflictScore, votes };
}

export { aggregate };
