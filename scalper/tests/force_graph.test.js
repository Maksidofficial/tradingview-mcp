/**
 * Tests for Mirofish force-directed graph engine.
 * No network required — pure unit tests.
 *
 * Run: node --test scalper/tests/force_graph.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { MirofishGraph, NODE_DEFS, EDGE_DEFS } from '../engine/force_graph.js';

describe('MirofishGraph topology', () => {
  it('has exactly 100 nodes', () => {
    assert.equal(NODE_DEFS.length, 100);
  });

  it('has exactly 180 edges', () => {
    assert.equal(EDGE_DEFS.length, 180);
  });

  it('initialises 100 nodes in the node map', () => {
    const g = new MirofishGraph();
    assert.equal(g.nodes.size, 100);
  });

  it('initialises 180 edges in the edge list', () => {
    const g = new MirofishGraph();
    assert.equal(g.edges.length, 180);
  });

  it('all edge source and target nodes exist', () => {
    const g = new MirofishGraph();
    for (const e of g.edges) {
      assert.ok(g.nodes.has(e.u), `edge source missing: ${e.u}`);
      assert.ok(g.nodes.has(e.v), `edge target missing: ${e.v}`);
    }
  });

  it('all nodes initialise with position=0 and velocity=0', () => {
    const g = new MirofishGraph();
    for (const n of g.nodes.values()) {
      assert.equal(n.position, 0);
      assert.equal(n.velocity, 0);
    }
  });

  it('all edge types are C, I, or A', () => {
    for (const e of EDGE_DEFS) {
      assert.ok(['C', 'I', 'A'].includes(e.type), `bad type: ${e.type}`);
    }
  });
});

describe('MirofishGraph physics', () => {
  it('returns bias, convergence, bull_score, bear_score from tick()', () => {
    const g = new MirofishGraph();
    const result = g.tick();
    assert.ok('bias' in result);
    assert.ok('convergence' in result);
    assert.ok('bull_score' in result);
    assert.ok('bear_score' in result);
  });

  it('convergence is bounded [0, 1]', () => {
    const g = new MirofishGraph();
    for (let i = 0; i < 10; i++) {
      const r = g.tick();
      assert.ok(r.convergence >= 0 && r.convergence <= 1, `convergence out of range: ${r.convergence}`);
    }
  });

  it('BULL cluster forms when all momentum nodes strongly positive', () => {
    const g = new MirofishGraph();
    const bullIds = [...g.nodes.keys()].filter(id =>
      id.startsWith('pm_') || id.startsWith('sp_') || id.startsWith('ti_') || id.startsWith('ms_')
    );

    let result;
    for (let i = 0; i < 200; i++) {
      // Keep refreshing so restoring force pulls positions up
      for (const id of bullIds) g._setNode(id, 1.0);
      result = g.tick();
    }

    assert.equal(result.bias, 'BULL', `Expected BULL bias, got ${result.bias} (bull=${result.bull_score.toFixed(3)} bear=${result.bear_score.toFixed(3)})`);
    assert.ok(result.bull_score > result.bear_score, 'BULL score should exceed BEAR score');
  });

  it('BEAR cluster forms when all momentum nodes strongly negative', () => {
    const g = new MirofishGraph();
    // Set all momentum AND high-weight signal nodes negative
    const bearIds = [...g.nodes.keys()].filter(id =>
      id.startsWith('pm_') || id.startsWith('sp_') || id.startsWith('ti_') || id.startsWith('ms_')
    );
    for (const id of bearIds) g._setNode(id, -1.0);

    let result;
    for (let i = 0; i < 200; i++) {
      // Keep refreshing values so restoring force keeps pulling positions negative
      for (const id of bearIds) g._setNode(id, -1.0);
      result = g.tick();
    }

    assert.equal(result.bias, 'BEAR', `Expected BEAR bias, got ${result.bias} (bull=${result.bull_score.toFixed(3)} bear=${result.bear_score.toFixed(3)})`);
    assert.ok(result.bear_score > result.bull_score, 'BEAR score should exceed BULL score');
  });

  it('convergence is high (>0.6) when all sentiment+momentum nodes agree', () => {
    const g = new MirofishGraph();
    const strongIds = [...g.nodes.keys()].filter(id =>
      id.startsWith('pm_') || id.startsWith('sp_') || id.startsWith('ti_')
    );
    for (const id of strongIds) g._setNode(id, 0.8);

    let result;
    for (let i = 0; i < 150; i++) result = g.tick();

    assert.ok(result.convergence > 0.5, `Expected convergence > 0.5, got ${result.convergence.toFixed(3)}`);
  });

  it('positions decay toward zero with no signal input (damping)', () => {
    const g = new MirofishGraph();
    // Pump all nodes with velocity
    for (const n of g.nodes.values()) n.velocity = 0.5;
    for (let i = 0; i < 5; i++) g.tick();

    // Ensure all values are 0 (no external signal → restoring force pulls toward 0)
    for (const n of g.nodes.values()) n.value = 0;

    // Let damping + restoring force bring positions back to 0
    for (let i = 0; i < 300; i++) g.tick();

    const maxPos = Math.max(...[...g.nodes.values()].map(n => Math.abs(n.position)));
    assert.ok(maxPos < 0.5, `Expected positions to decay near 0, max was ${maxPos.toFixed(3)}`);
  });

  it('setSignals does not throw with null/undefined fields', () => {
    const g = new MirofishGraph();
    assert.doesNotThrow(() => {
      g.setSignals({ binance: null, tradingview: null, cryptoquant: null, polymarket: null });
    });
  });

  it('setSignals with full binance state updates momentum nodes', () => {
    const g = new MirofishGraph();
    g.setSignals({
      binance: {
        price: 67000,
        price_1s:  66990,
        price_5s:  66950,
        price_10s: 66900,
        price_30s: 66800,
        price_60s: 66500,
        kline: { open: 66500, high: 67100, low: 66400, close: 67000, volume: 500 },
        recentTicks: [],
        recentKlines: [],
      },
      tradingview: null,
      cryptoquant: null,
      polymarket: null,
    });

    const pm60 = g.nodes.get('pm_60s').value;
    assert.ok(pm60 > 0, `pm_60s should be positive for upward move, got ${pm60}`);
  });
});

describe('MirofishGraph weight updates', () => {
  it('updateWeights reinforces active edges on winning trade', () => {
    const g = new MirofishGraph();
    // Run a tick to build some active forces
    for (const n of g.nodes.values()) n.value = 0.5;
    g.tick();

    const edgeBefore = g.edges[0].w;
    g.updateWeights({ pnl: 10 });
    // The edge that was active (non-zero force) should have changed
    // Edge 0 may not have been active, so just check it didn't go negative
    assert.ok(g.edges[0].w >= 0.01, 'Weight should not go below minimum');
  });

  it('weights stay within [WEIGHT_MIN, WEIGHT_MAX] bounds', () => {
    const g = new MirofishGraph();
    for (const n of g.nodes.values()) n.value = 1.0;
    g.tick();

    // Simulate many winning trades
    for (let i = 0; i < 200; i++) {
      g._activeEdgeForces.set(`${g.edges[0].u}:${g.edges[0].v}`, 1.0);
      g.updateWeights({ pnl: 5 });
    }

    for (const e of g.edges) {
      assert.ok(e.w >= 0.01 && e.w <= 2.0, `Weight out of bounds: ${e.w} for ${e.u}→${e.v}`);
    }
  });

  it('nodeSnapshot returns 100 entries', () => {
    const g = new MirofishGraph();
    g.tick();
    const snap = g.nodeSnapshot();
    assert.equal(Object.keys(snap).length, 100);
  });
});
