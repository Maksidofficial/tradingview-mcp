/**
 * Integration tests — full pipeline with mocked feeds.
 * No network required.
 *
 * Run: node --test scalper/tests/integration.test.js
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { MirofishGraph } from '../engine/force_graph.js';
import { detectEdge }    from '../engine/edge_detector.js';
import { aggregate }     from '../engine/signal.js';
import { RiskManager }   from '../execution/risk.js';
import { CONFIG }        from '../config.js';

// ── Mock feeds ─────────────────────────────────────────────────────────────────

function makeBinanceState(overrides = {}) {
  return {
    price:     67335,
    price_1s:  67330,
    price_5s:  67300,
    price_10s: 67200,
    price_30s: 67100,
    price_60s: 67000,
    kline: { open: 67000, high: 67400, low: 66900, close: 67335, volume: 850, isFinal: false },
    recentTicks: Array.from({ length: 20 }, (_, i) => ({
      price: 67000 + i * 17,
      qty:   0.05,
      time:  Date.now() - (20 - i) * 500,
      isBuyer: true,  // all buys = bullish
    })),
    recentKlines: [],
    connected: true,
    ...overrides,
  };
}

function makePMState(upMid = 0.50, askDepth = 3000) {
  return {
    up:   { tokenId: 'up123', mid: upMid,       bestBid: upMid - 0.01,       bestAsk: upMid + 0.01,       askDepth, bidDepth: askDepth },
    down: { tokenId: 'dn123', mid: 1 - upMid,   bestBid: (1-upMid) - 0.01,  bestAsk: (1-upMid) + 0.01,  askDepth, bidDepth: askDepth },
    connected: true,
  };
}

function makeSignal(direction = 'UP', confidence = 0.75) {
  return { direction, confidence, conflicts: [], votes: [] };
}

function makeFGResult(bias = 'BULL', convergence = 0.75) {
  return { bias, convergence, bull_score: 0.8, bear_score: 0.3 };
}

// ── Mock executor (no real polymarket.js import) ──────────────────────────────

class MockExecutor {
  constructor(risk, fg) {
    this.risk = risk;
    this.fg   = fg;
    this.log  = [];
  }

  async execute(edge, signal) {
    const t0 = performance.now();

    const guard = this.risk.canTrade();
    if (!guard.ok) {
      this.log.push({ result: 'skip', reason: guard.reason });
      return { skipped: true, reason: guard.reason };
    }

    if (!signal.direction) {
      this.log.push({ result: 'skip', reason: 'no_signal' });
      return { skipped: true, reason: 'no signal' };
    }

    if (signal.confidence < (CONFIG.MIN_CONFIDENCE ?? 0.5)) {
      this.log.push({ result: 'skip', reason: 'low_confidence' });
      return { skipped: true, reason: 'low confidence' };
    }

    if (signal.conflicts.length > 0 && signal.confidence < 0.7) {
      this.log.push({ result: 'skip', reason: 'conflicts' });
      return { skipped: true, reason: 'conflicts' };
    }

    if (signal.direction !== edge.direction) {
      this.log.push({ result: 'skip', reason: 'direction_mismatch' });
      return { skipped: true, reason: 'mismatch' };
    }

    const entryPrice = edge.impliedProb ?? 0.52;
    const { shares, cost_usdc, max_loss } = this.risk.sizePosition(entryPrice, signal.confidence);

    const record = this.risk.recordPaperTrade({
      direction: edge.direction,
      entryPrice,
      shares,
      costUsdc: cost_usdc,
      latencyMs: performance.now() - t0,
      edge,
      signal,
    });

    this.log.push({ result: 'trade', record });
    return { paper: true, record, latency_ms: record.latencyMs };
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Integration — full pipeline', () => {
  let risk, fg, executor;

  beforeEach(() => {
    risk     = new RiskManager();
    fg       = new MirofishGraph();
    executor = new MockExecutor(risk, fg);
  });

  it('force graph updates when Binance aggTrade fires', () => {
    const bState = makeBinanceState();
    fg.setSignals({ binance: bState, tradingview: null, cryptoquant: null, polymarket: null });
    const result = fg.tick();
    assert.ok(['BULL', 'BEAR'].includes(result.bias));
    assert.ok(result.convergence >= 0 && result.convergence <= 1);
  });

  it('edge detected with 0.5% spot move and stale PM (0.4% lag edge)', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);  // PM not yet moved
    const edge = detectEdge(bState, pmState);
    assert.ok(edge !== null, 'Expected edge with 0.5% spot move vs stale PM');
    assert.equal(edge.direction, 'UP');
  });

  it('full pipeline: edge + consensus signal → paper trade logged', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);
    const edge = detectEdge(bState, pmState);
    assert.ok(edge !== null);

    const sig = makeSignal('UP', 0.80);
    const result = await executor.execute(edge, sig);

    assert.equal(result.paper, true);
    assert.equal(executor.log.length, 1);
    assert.equal(executor.log[0].result, 'trade');
    assert.equal(risk.stats().totalTrades, 1);
  });

  it('full pipeline: edge + conflicting signals with low confidence → trade skipped', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);
    const edge = detectEdge(bState, pmState);
    assert.ok(edge !== null);

    const conflictedSig = {
      direction: 'UP',
      confidence: 0.55,
      conflicts: ['macd(-80)', 'cqFlow(-500)'],  // conflicting signals
      votes: [],
    };
    const result = await executor.execute(edge, conflictedSig);
    assert.equal(result.skipped, true);
    assert.equal(executor.log[0].reason, 'conflicts');
    assert.equal(risk.stats().totalTrades, 0);
  });

  it('full pipeline: daily cap hit → trade skipped even with valid edge + signal', async () => {
    risk.dailyExposure = CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT;  // cap hit

    const bState = makeBinanceState();
    const pmState = makePMState(0.50);
    const edge = detectEdge(bState, pmState);
    assert.ok(edge !== null);

    const sig = makeSignal('UP', 0.85);
    const result = await executor.execute(edge, sig);
    assert.equal(result.skipped, true);
    assert.ok(result.reason.includes('cap') || result.reason.includes('exposure'));
  });

  it('full pipeline: direction mismatch → trade skipped', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);
    const edge = detectEdge(bState, pmState);
    assert.ok(edge !== null);
    assert.equal(edge.direction, 'UP');

    // Signal says DOWN but edge says UP → mismatch
    const mismatchSig = makeSignal('DOWN', 0.80);
    const result = await executor.execute(edge, mismatchSig);
    assert.equal(result.skipped, true);
  });

  it('full pipeline: low confidence → trade skipped', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);
    const edge = detectEdge(bState, pmState);
    assert.ok(edge !== null);

    const lowSig = makeSignal('UP', 0.3);  // below MIN_CONFIDENCE
    const result = await executor.execute(edge, lowSig);
    assert.equal(result.skipped, true);
  });

  it('latency: full in-memory pipeline completes in < 50ms', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);

    const t0 = performance.now();

    fg.setSignals({ binance: bState, tradingview: null, cryptoquant: null, polymarket: pmState });
    fg.tick();

    const edge = detectEdge(bState, pmState);
    const sig  = aggregate({
      binance: bState,
      tradingview: null,
      cryptoquant: { netFlow: 300 },
      polymarket: pmState,
      forceGraph: makeFGResult(),
    });

    if (edge && sig.direction) {
      await executor.execute(edge, sig);
    }

    const elapsed = performance.now() - t0;
    assert.ok(elapsed < 50, `Pipeline took ${elapsed.toFixed(1)}ms, expected < 50ms`);
  });

  it('multiple trades accumulate correctly in risk state', async () => {
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);
    const edge = detectEdge(bState, pmState);
    const sig  = makeSignal('UP', 0.80);

    // Execute 3 trades
    for (let i = 0; i < 3; i++) {
      if (risk.canTrade().ok) await executor.execute(edge, sig);
    }

    assert.ok(risk.stats().totalTrades <= 3);
    assert.ok(risk.stats().dailyExposure > 0);
  });
});

describe('Integration — signal aggregation with live-ish data', () => {
  it('produces UP signal from bull Binance data + force graph', () => {
    const fg = new MirofishGraph();
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);

    fg.setSignals({ binance: bState, tradingview: null, cryptoquant: null, polymarket: pmState });
    for (let i = 0; i < 20; i++) fg.tick();  // settle

    const fgResult = fg.tick();
    const sig = aggregate({
      binance: bState,
      tradingview: { rsi: 28, macdHist: 50, ema9: 67280, ema21: 67100, available: true },
      cryptoquant: { netFlow: 400 },
      polymarket: pmState,
      forceGraph: fgResult,
    });

    // With strongly bullish data, direction should be UP or null (if conflict)
    assert.ok(sig.direction === 'UP' || sig.direction === null);
    assert.ok(sig.confidence >= 0 && sig.confidence <= 1);
  });

  it('edge + aggregated signal: detects and aggregates without error', () => {
    const fg = new MirofishGraph();
    const bState = makeBinanceState();
    const pmState = makePMState(0.50);

    fg.setSignals({ binance: bState, tradingview: null, cryptoquant: null, polymarket: pmState });
    const fgResult = fg.tick();

    const edge = detectEdge(bState, pmState);
    const sig  = aggregate({
      binance: bState,
      tradingview: null,
      cryptoquant: null,
      polymarket: pmState,
      forceGraph: fgResult,
    });

    assert.ok(typeof sig.direction === 'string' || sig.direction === null);
    assert.ok(typeof sig.confidence === 'number');
    assert.ok(Array.isArray(sig.conflicts));
  });
});
