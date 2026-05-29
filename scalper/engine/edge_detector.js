import { CONFIG } from '../config.js';

// Sigmoid: maps any real to (0,1). σ(0)=0.5, σ(±3)≈0.95/0.05
function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }

// Normalise spot momentum into an implied probability of UP.
// 0.3% move → 50th percentile → σ(1) ≈ 0.73
// Reference scale: 0.3% per LAG_THRESHOLD (≈ the unit we care about)
function momentumToImpliedProb(spotChangePct) {
  const k = spotChangePct / (CONFIG.LAG_THRESHOLD_PCT ?? 0.003);
  return sigmoid(k);
}

// ── Main edge detection ───────────────────────────────────────────────────────

/**
 * Detect whether Polymarket is lagging BTC spot price by ≥ 0.3%.
 *
 * @param {object} binanceState - from binance.getState()
 * @param {object} pmState      - from polymarket.getState()
 * @returns {{ direction, lag_pct, confidence, impliedProb, momentumProb } | null}
 */
function detectEdge(binanceState, pmState) {
  const price    = binanceState?.price;
  const price60s = binanceState?.price_60s;
  if (!price || !price60s || price60s === 0) return null;

  const spotChangePct = (price - price60s) / price60s;
  const momentumProb  = momentumToImpliedProb(spotChangePct);

  // Polymarket UP contract mid-price (direct probability, 0→1)
  const upMid   = pmState?.up?.mid;
  const downMid = pmState?.down?.mid;
  if (upMid == null) return null;

  // How far is the market lagging the momentum signal?
  const impliedProb = upMid;
  const lag = momentumProb - impliedProb;  // positive → market under-pricing UP
  const lagPct = Math.abs(lag);

  if (lagPct < (CONFIG.LAG_THRESHOLD_PCT ?? 0.003)) return null;

  // Direction: if lag > 0 → market is cheap on UP → buy UP
  //            if lag < 0 → market is cheap on DOWN → buy DOWN
  const direction = lag > 0 ? 'UP' : 'DOWN';

  // Check liquidity on the side we'd take
  const liquidity = direction === 'UP'
    ? (pmState?.up?.askDepth ?? 0)
    : (pmState?.down?.askDepth ?? 0);

  if (liquidity < (CONFIG.MIN_LIQUIDITY_USDC ?? 1000)) return null;

  // Confidence: proportional to lag magnitude (capped at 1)
  const confidence = Math.min(1, lagPct / 0.008);

  return {
    direction,
    lag_pct:      lagPct,
    confidence,
    impliedProb,
    momentumProb,
    spotChangePct,
    liquidity,
    ts: Date.now(),
  };
}

export { detectEdge, momentumToImpliedProb, sigmoid };
