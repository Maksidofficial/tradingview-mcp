/**
 * Tests for execution/risk.js
 * No network required — pure unit tests.
 *
 * Run: node --test scalper/tests/risk.test.js
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { RiskManager } from '../execution/risk.js';
import { CONFIG } from '../config.js';

function makeRisk() {
  return new RiskManager();
}

// ── canTrade ─────────────────────────────────────────────────────────────────

describe('RiskManager.canTrade()', () => {
  it('allows trade at session start', () => {
    const r = makeRisk();
    assert.deepEqual(r.canTrade(), { ok: true });
  });

  it('blocks when dailyExposure hits 2% cap', () => {
    const r = makeRisk();
    r.dailyExposure = CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT;
    const result = r.canTrade();
    assert.equal(result.ok, false);
    assert.ok(result.reason.includes('cap'));
  });

  it('blocks when dailyExposure exceeds 2% cap', () => {
    const r = makeRisk();
    r.dailyExposure = CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT * 1.1;
    assert.equal(r.canTrade().ok, false);
  });

  it('allows trade just below daily exposure cap', () => {
    const r = makeRisk();
    r.dailyExposure = CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT * 0.99;
    assert.equal(r.canTrade().ok, true);
  });

  it('blocks when dailyPnL hits daily loss cap', () => {
    const r = makeRisk();
    r.dailyPnL = -(CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT);
    const result = r.canTrade();
    assert.equal(result.ok, false);
    assert.ok(result.reason.includes('loss cap') || result.reason.includes('daily'));
  });

  it('blocks when dailyPnL exceeds daily loss cap', () => {
    const r = makeRisk();
    r.dailyPnL = -(CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT * 1.5);
    assert.equal(r.canTrade().ok, false);
  });

  it('allows trade with small daily loss', () => {
    const r = makeRisk();
    r.dailyPnL = -(CONFIG.CAPITAL_USDC * CONFIG.DAILY_CAP_PCT * 0.5);
    assert.equal(r.canTrade().ok, true);
  });
});

// ── sizePosition ──────────────────────────────────────────────────────────────

describe('RiskManager.sizePosition()', () => {
  it('max_loss equals exactly 0.5% of capital', () => {
    const r = makeRisk();
    const { max_loss } = r.sizePosition(0.50);
    const expected = CONFIG.CAPITAL_USDC * CONFIG.PER_TRADE_RISK_PCT;
    assert.ok(Math.abs(max_loss - expected) < 0.001, `Expected ${expected}, got ${max_loss}`);
  });

  it('returns positive shares and cost', () => {
    const r = makeRisk();
    const { shares, cost_usdc } = r.sizePosition(0.50);
    assert.ok(shares > 0);
    assert.ok(cost_usdc > 0);
  });

  it('cost_usdc < max_loss (buying a $0.50 contract risks only $0.50 per share)', () => {
    const r = makeRisk();
    const { cost_usdc, max_loss } = r.sizePosition(0.50);
    assert.ok(cost_usdc <= max_loss * 1.01, `cost ${cost_usdc} should be ≤ max_loss ${max_loss}`);
  });

  it('higher entry price → fewer shares (fixed-risk sizing)', () => {
    const r = makeRisk();
    const { shares: shares_low  } = r.sizePosition(0.30);
    const { shares: shares_high } = r.sizePosition(0.70);
    assert.ok(shares_high < shares_low, 'Higher-priced contracts should buy fewer shares');
  });

  it('clips extreme prices to valid range [0.01, 0.99]', () => {
    const r = makeRisk();
    assert.doesNotThrow(() => r.sizePosition(0));
    assert.doesNotThrow(() => r.sizePosition(1));
    assert.doesNotThrow(() => r.sizePosition(-0.5));
    assert.doesNotThrow(() => r.sizePosition(1.5));
  });
});

// ── openPosition / closePosition ──────────────────────────────────────────────

describe('RiskManager position lifecycle', () => {
  it('openPosition adds to openPositions and updates dailyExposure', () => {
    const r = makeRisk();
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice: 0.52, shares: 10, costUsdc: 5.2 });
    assert.equal(r.openPositions.length, 1);
    assert.ok(r.dailyExposure > 0);
  });

  it('closePosition removes from openPositions and updates dailyPnL', () => {
    const r = makeRisk();
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice: 0.52, shares: 10, costUsdc: 5.2 });
    const record = r.closePosition('T1', 0.57);
    assert.ok(record !== null);
    assert.equal(r.openPositions.length, 0);
    assert.ok(record.pnl > 0);  // closed at higher price
    assert.ok(r.dailyPnL > 0);
  });

  it('closePosition returns null for unknown id', () => {
    const r = makeRisk();
    const result = r.closePosition('NONEXISTENT', 0.5);
    assert.equal(result, null);
  });

  it('winning trade increases dailyPnL', () => {
    const r = makeRisk();
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice: 0.50, shares: 10, costUsdc: 5 });
    r.closePosition('T1', 0.60);
    assert.ok(r.dailyPnL > 0);
  });

  it('losing trade decreases dailyPnL', () => {
    const r = makeRisk();
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice: 0.50, shares: 10, costUsdc: 5 });
    r.closePosition('T1', 0.45);
    assert.ok(r.dailyPnL < 0);
  });
});

// ── checkHardStops ────────────────────────────────────────────────────────────

describe('RiskManager.checkHardStops()', () => {
  it('triggers hard stop at -0.4% position loss', () => {
    const r = makeRisk();
    const entryPrice = 0.5;
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice, shares: 20, costUsdc: 10 });

    // Move price down by exactly HARD_STOP_PCT
    const stopPrice = entryPrice * (1 - CONFIG.HARD_STOP_PCT);
    const closed = r.checkHardStops({ up: stopPrice });
    assert.equal(closed.length, 1);
    assert.equal(closed[0].reason, 'hard_stop');
  });

  it('does not trigger hard stop above threshold', () => {
    const r = makeRisk();
    const entryPrice = 0.5;
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice, shares: 20, costUsdc: 10 });

    const aboveStop = entryPrice * (1 - CONFIG.HARD_STOP_PCT * 0.5);
    const closed = r.checkHardStops({ up: aboveStop });
    assert.equal(closed.length, 0);
  });

  it('closes multiple positions at hard stop', () => {
    const r = makeRisk();
    r.openPosition({ id: 'T1', direction: 'UP', entryPrice: 0.5, shares: 10, costUsdc: 5 });
    r.openPosition({ id: 'T2', direction: 'UP', entryPrice: 0.5, shares: 10, costUsdc: 5 });

    const stopPrice = 0.5 * (1 - CONFIG.HARD_STOP_PCT * 1.1);
    const closed = r.checkHardStops({ up: stopPrice });
    assert.equal(closed.length, 2);
  });

  it('returns empty array when no positions', () => {
    const r = makeRisk();
    assert.deepEqual(r.checkHardStops({ up: 0.4 }), []);
  });
});

// ── stats() ───────────────────────────────────────────────────────────────────

describe('RiskManager.stats()', () => {
  it('returns expected fields', () => {
    const r = makeRisk();
    const s = r.stats();
    assert.ok('dailyPnL' in s);
    assert.ok('dailyExposure' in s);
    assert.ok('dailyCapUsed' in s);
    assert.ok('openCount' in s);
    assert.ok('totalTrades' in s);
    assert.ok('capital' in s);
  });

  it('dailyCapUsed is 0 at session start', () => {
    const r = makeRisk();
    assert.equal(r.stats().dailyCapUsed, 0);
  });

  it('totalTrades increments on paper trade record', () => {
    const r = makeRisk();
    r.recordPaperTrade({
      direction: 'UP', entryPrice: 0.52, shares: 10, costUsdc: 5.2,
      latencyMs: 35, edge: {}, signal: {},
    });
    assert.equal(r.stats().totalTrades, 1);
  });
});
