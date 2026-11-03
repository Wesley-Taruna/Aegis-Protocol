'use strict';

/**
 * Aegis Protocol — local web UI server.
 *
 * Serves an interactive test console at http://localhost:3000 and streams
 * live handshake progress over Server-Sent Events (SSE).
 */

const express = require('express');
const path = require('path');

const { FAULT_MODES } = require('./src/protocol');
const { runBatch } = require('./src/runner');
const {
  generateResearchSummary,
  buildExportPayload,
} = require('./src/report');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory cache of the most recent full run, used by the export endpoint.
let lastRun = null;

/**
 * SSE endpoint: GET /api/run?count=1000&fault=legitimate
 * Streams `progress` events while running, then a final `done` event.
 */
app.get('/api/run', (req, res) => {
  const count = Math.max(1, parseInt(req.query.count, 10) || 1000);
  const fault = FAULT_MODES.includes(req.query.fault) ? req.query.fault : 'legitimate';

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });

  const send = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  send('start', { count, fault });

  // Run on the next tick so the start event flushes first. The batch is
  // synchronous CPU work; progress events are buffered and flushed together,
  // which is fine for a local research tool.
  setImmediate(() => {
    try {
      const { summary, results } = runBatch({
        count,
        fault,
        onProgress: (progress) => send('progress', progress),
      });

      lastRun = { summary, results, fault, generatedAt: new Date().toISOString() };

      send('done', {
        summary,
        researchSummary: generateResearchSummary(summary),
        // Send only the last 100 rows over the wire; full set is via /api/export.
        recentResults: results.slice(-100),
        latencies: results.map((r) => r.latencyMs),
      });
    } catch (err) {
      send('error', { message: err.message });
    } finally {
      res.end();
    }
  });

  req.on('close', () => {
    res.end();
  });
});

/**
 * GET /api/export — download the full payload of the most recent run as JSON.
 */
app.get('/api/export', (req, res) => {
  if (!lastRun) {
    res.status(404).json({ error: 'No run available yet. Run a test first.' });
    return;
  }
  const payload = buildExportPayload(lastRun.summary, lastRun.results);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="aegis-results-${lastRun.fault}-${Date.now()}.json"`
  );
  res.send(JSON.stringify(payload, null, 2));
});

app.get('/api/fault-modes', (req, res) => {
  res.json({ faultModes: FAULT_MODES });
});

app.listen(PORT, () => {
  console.log(`Aegis Protocol web UI running at http://localhost:${PORT}`);
  console.log('Press Ctrl+C to stop.');
});
