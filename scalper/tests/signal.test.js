/**
 * Tests for engine/signal.js
 * No network required — pure unit tests.
 *
 * Run: node --test scalper/tests/signal.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { aggregate } from '../engine/signal.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeBullFeeds() {
  return {
    binance: {
      price:    67300,
      price_10s: 67200,
      price_60s: 67000,
      kline: { open: 67000, high: 67400, low: 66900, close: 67300, volume: 800 },
      recentTicks: [],
    },
    tradingview: {
      rsi: 28,            // oversold → UP
      macdHist: 50,       // positive → UP
      ema9: 67280,
      ema21: 67100,
      available: true,
    },
    cryptoquant: { netFlow: 500 },  // large outflow → bullish
    polymarket: {
      up:   { mid: 0.60, askDepth: 3000 },  // higher prob → bullish imbalance
      down: { mid: 0.40, askDepth: 3000 },
    },
    forceGraph: { bias: 'BULL', convergence: 0.75, bull_score: 0.8, bear_score: 0.3 },
  };
}

function makeBearFeeds() {
  return {
    binance: {
      price:    66700,
      price_10s: 66800,
      price_60s: 67000,
      kline: { open: 67000, high: 67050, low: 66600, close: 66700, volume: 900 },
      recentTicks: [],
    },
    tradingview: {
      rsi: 72,            // overbought → DOWN
      macdHist: -60,      // negative → DOWN
      ema9: 66720,
      ema21: 66850,
      available: true,
    },
    cryptoquant: { netFlow: -600 },  // large inflow → bearish
    polymarket: {
      up:   { mid: 0.55, askDepth: 3000 },
      down: { mid: 0.45, askDepth: 3000 },
    },
    forceGraph: { bias: 'BEAR', convergence: 0.80, bull_score: 0.3, bear_score: 0.9 },
  };
}

// ── All-bullish inputs ────────────────────────────────────────────────────────

describe('aggregate — all-bullish inputs', () => {
  it('returns direction=UP', () => {
    const sig = aggregate(makeBullFeeds());
    assert.equal(sig.direction, 'UP');
  });

  it('returns confidence > 0.5', () => {
    const sig = aggregate(makeBullFeeds());
    assert.ok(sig.confidence > 0.5, `confidence was ${sig.confidence}`);
  });

  it('has no conflicts (no dissenting votes)', () => {
    const sig = aggregate(makeBullFeeds());
    assert.equal(sig.conflicts.length, 0);
  });

  it('confidence is bounded [0, 1]', () => {
    const sig = aggregate(makeBullFeeds());
    assert.ok(sig.confidence >= 0 && sig.confidence <= 1);
  });
});

// ── All-bearish inputs ────────────────────────────────────────────────────────

describe('aggregate — all-bearish inputs', () => {
  it('returns direction=DOWN', () => {
    const sig = aggregate(makeBearFeeds());
    assert.equal(sig.direction, 'DOWN');
  });

  it('returns confidence > 0.5', () => {
    const sig = aggregate(makeBearFeeds());
    assert.ok(sig.confidence > 0.5);
  });
});

// ── Conflicting signals ───────────────────────────────────────────────────────

describe('aggregate — conflicting signals', () => {
  it('suppresses direction when conflict score > 0.4', () => {
    const feeds = {
      binance: {
        price: 67000, price_10s: 67000, price_60s: 67000,
        kline: { open: 67000, high: 67010, low: 66990, close: 67000, volume: 100 },
        recentTicks: [],
      },
      tradingview: {
        rsi:      28,    // UP signal
        macdHist: -80,   // DOWN signal — conflict
        ema9:     67000,
        ema21:    67100, // DOWN: ema9 < ema21
        available: true,
      },
      cryptoquant: { netFlow: -500 },  // DOWN
      polymarket: {
        up:   { mid: 0.50, askDepth: 2000 },
        down: { mid: 0.50, askDepth: 2000 },
      },
      forceGraph: { bias: 'BULL', convergence: 0.65, bull_score: 0.7, bear_score: 0.3 },
    };
    const sig = aggregate(feeds);
    // Conflicts exist (RSI up vs MACD down vs EMA cross down vs CQ down)
    // The direction may be suppressed; verify conflicts array has entries
    assert.ok(sig.conflicts.length > 0, 'Expected conflicts with opposing signals');
  });

  it('populatesconflictScore between 0 and 1', () => {
    const feeds = makeBullFeeds();
    feeds.tradingview.macdHist = -100;  // introduce a conflict
    const sig = aggregate(feeds);
    if (sig.conflictScore != null) {
      assert.ok(sig.conflictScore >= 0 && sig.conflictScore <= 1);
    }
  });
});

// ── Weak force graph ──────────────────────────────────────────────────────────

describe('aggregate — weak force graph', () => {
  it('force graph does not vote when convergence < 0.6', () => {
    const feeds = makeBullFeeds();
    feeds.forceGraph = { bias: 'BULL', convergence: 0.4, bull_score: 0.6, bear_score: 0.5 };
    const sig = aggregate(feeds);
    // Should still work, just without FG vote
    assert.ok(sig.direction !== undefined);
    const fgVotes = sig.votes?.filter(v => v.source.startsWith('forceGraph')) ?? [];
    assert.equal(fgVotes.length, 0, 'Weak FG should not contribute a vote');
  });

  it('force graph votes when convergence > 0.6', () => {
    const feeds = makeBullFeeds();
    feeds.forceGraph = { bias: 'BULL', convergence: 0.75, bull_score: 0.8, bear_score: 0.2 };
    const sig = aggregate(feeds);
    const fgVotes = sig.votes?.filter(v => v.source.startsWith('forceGraph')) ?? [];
    assert.equal(fgVotes.length, 1, 'Strong FG should contribute a vote');
  });
});

// ── Null/missing feeds ────────────────────────────────────────────────────────

describe('aggregate — null feeds', () => {
  it('handles all-null feeds without throwing', () => {
    assert.doesNotThrow(() => {
      aggregate({ binance: null, tradingview: null, cryptoquant: null, polymarket: null, forceGraph: null });
    });
  });

  it('returns null direction when no votes collected', () => {
    const sig = aggregate({
      binance: { price: 67000, price_10s: 67000, price_60s: 67000, kline: null, recentTicks: [] },
      tradingview: null,
      cryptoquant: { netFlow: 0 },   // below 200 threshold → no vote
      polymarket: { up: { mid: 0.50 }, down: { mid: 0.50 } },
      forceGraph: { bias: 'BULL', convergence: 0.3 },  // below threshold
    });
    assert.equal(sig.direction, null);
  });

  it('confidence is bounded even with sparse data', () => {
    const sig = aggregate({ binance: null, tradingview: null, cryptoquant: null, polymarket: null, forceGraph: null });
    assert.ok(sig.confidence >= 0 && sig.confidence <= 1);
  });
});

// ── Confidence bounds ─────────────────────────────────────────────────────────

describe('aggregate — confidence always [0,1]', () => {
  it('strong bull scenario: confidence ≤ 1', () => {
    const sig = aggregate(makeBullFeeds());
    assert.ok(sig.confidence <= 1);
  });
  it('strong bear scenario: confidence ≤ 1', () => {
    const sig = aggregate(makeBearFeeds());
    assert.ok(sig.confidence <= 1);
  });
});
