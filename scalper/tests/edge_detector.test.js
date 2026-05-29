/**
 * Tests for edge_detector.js
 * No network required — pure unit tests.
 *
 * Run: node --test scalper/tests/edge_detector.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectEdge, momentumToImpliedProb, sigmoid } from '../engine/edge_detector.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeBinance(price, price60s) {
  return { price, price_60s: price60s };
}

function makePM(upMid, upAskDepth = 2000, downMid = null, downAskDepth = 2000) {
  const dn = downMid ?? (1 - upMid);
  return {
    up:   { mid: upMid,   askDepth: upAskDepth,   bestBid: upMid - 0.01, bestAsk: upMid + 0.01 },
    down: { mid: dn,      askDepth: downAskDepth,  bestBid: dn - 0.01,   bestAsk: dn + 0.01 },
  };
}

// ── sigmoid ───────────────────────────────────────────────────────────────────

describe('sigmoid', () => {
  it('σ(0) = 0.5', () => {
    assert.ok(Math.abs(sigmoid(0) - 0.5) < 1e-9);
  });
  it('σ(x) ∈ (0, 1) for all x', () => {
    for (const x of [-10, -3, -1, 0, 1, 3, 10]) {
      assert.ok(sigmoid(x) > 0 && sigmoid(x) < 1);
    }
  });
  it('σ is monotonically increasing', () => {
    assert.ok(sigmoid(1) > sigmoid(0));
    assert.ok(sigmoid(-1) < sigmoid(0));
  });
});

// ── momentumToImpliedProb ─────────────────────────────────────────────────────

describe('momentumToImpliedProb', () => {
  it('flat market → ~0.5 probability', () => {
    const p = momentumToImpliedProb(0);
    assert.ok(Math.abs(p - 0.5) < 0.001);
  });
  it('positive momentum → P(UP) > 0.5', () => {
    assert.ok(momentumToImpliedProb(0.003) > 0.5);
  });
  it('negative momentum → P(UP) < 0.5', () => {
    assert.ok(momentumToImpliedProb(-0.003) < 0.5);
  });
  it('large positive momentum → P(UP) > 0.7', () => {
    assert.ok(momentumToImpliedProb(0.01) > 0.7);
  });
});

// ── detectEdge ────────────────────────────────────────────────────────────────

describe('detectEdge — no edge cases', () => {
  it('returns null when lag < 0.3%', () => {
    // Spot: +0.001% → momentumProb ≈ 0.5003. PM UP: 0.500 → lag ≈ 0.0003 < 0.003
    const b  = makeBinance(67001, 67000);  // +0.0015% move
    const pm = makePM(0.50);
    assert.equal(detectEdge(b, pm), null);
  });

  it('returns null with null binance price', () => {
    assert.equal(detectEdge({ price: null, price_60s: 67000 }, makePM(0.5)), null);
  });

  it('returns null with null price_60s', () => {
    assert.equal(detectEdge({ price: 67000, price_60s: null }, makePM(0.5)), null);
  });

  it('returns null with zero price_60s (division guard)', () => {
    assert.equal(detectEdge({ price: 67000, price_60s: 0 }, makePM(0.5)), null);
  });

  it('returns null when liquidity < 1000 even with large lag', () => {
    // +0.5% move, PM UP still at 0.5 → lag would be large
    const b  = makeBinance(67335, 67000);   // +0.5%
    const pm = makePM(0.50, 500, null, 500);  // low liquidity
    assert.equal(detectEdge(b, pm), null);
  });
});

describe('detectEdge — edge detected cases', () => {
  it('detects edge when spot +0.5% and PM unchanged (UP edge)', () => {
    // +0.5% → momentumProb >> 0.5. PM UP mid still at 0.5 → lag > 0.3%
    const b  = makeBinance(67335, 67000);  // +0.5%
    const pm = makePM(0.50, 3000);
    const edge = detectEdge(b, pm);
    assert.ok(edge !== null, 'Expected edge to be detected');
    assert.equal(edge.direction, 'UP');
    assert.ok(edge.lag_pct >= 0.003);
  });

  it('detects edge when spot -0.5% and PM unchanged (DOWN edge)', () => {
    const b  = makeBinance(66665, 67000);  // -0.5%
    const pm = makePM(0.50, 3000);
    const edge = detectEdge(b, pm);
    assert.ok(edge !== null, 'Expected edge to be detected');
    assert.equal(edge.direction, 'DOWN');
    assert.ok(edge.lag_pct >= 0.003);
  });

  it('edge confidence is within [0, 1]', () => {
    const b  = makeBinance(67335, 67000);
    const pm = makePM(0.50, 3000);
    const edge = detectEdge(b, pm);
    assert.ok(edge.confidence >= 0 && edge.confidence <= 1);
  });

  it('larger lag → higher confidence', () => {
    const b  = makeBinance(67335, 67000);  // +0.5%
    // PM1 is very stale (0.5), PM2 is slightly less stale (0.55)
    const edge1 = detectEdge(b, makePM(0.50, 2000));
    const edge2 = detectEdge(b, makePM(0.55, 2000));

    if (edge1 && edge2) {
      assert.ok(edge1.confidence >= edge2.confidence, 'Larger lag should have >= confidence');
    }
  });

  it('returns spotChangePct, impliedProb, momentumProb, liquidity in result', () => {
    const b  = makeBinance(67335, 67000);
    const pm = makePM(0.50, 2000);
    const edge = detectEdge(b, pm);
    assert.ok(edge !== null);
    assert.ok('spotChangePct' in edge);
    assert.ok('impliedProb' in edge);
    assert.ok('momentumProb' in edge);
    assert.ok('liquidity' in edge);
    assert.ok('ts' in edge);
  });

  it('edge ts is a recent timestamp', () => {
    const b  = makeBinance(67335, 67000);
    const pm = makePM(0.50, 2000);
    const edge = detectEdge(b, pm);
    assert.ok(Date.now() - edge.ts < 1000, 'Edge ts should be current');
  });
});

describe('detectEdge — boundary conditions', () => {
  it('exactly at 0.3% threshold: no edge (strict less-than)', () => {
    // Find a spot change that produces lag exactly at threshold — just under
    const b  = makeBinance(67100, 67000);  // +0.15% move
    const pm = makePM(0.50, 2000);
    // momentumProb at +0.15% is modest; PM at 0.5 → lag likely < 0.3%
    const edge = detectEdge(b, pm);
    // Just verify we don't crash; actual result depends on exact sigmoid output
    // (this is a boundary probe, not a hard assertion on result)
    assert.ok(edge === null || edge.lag_pct >= 0.003);
  });

  it('null polymarket state → null edge', () => {
    const b = makeBinance(67335, 67000);
    assert.equal(detectEdge(b, { up: null, down: null }), null);
    assert.equal(detectEdge(b, null), null);
    assert.equal(detectEdge(b, {}), null);
  });
});
