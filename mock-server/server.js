'use strict';

/**
 * PhishGuard Local - Isolated Localhost Mock Server
 * Serves safe and simulated phishing test pages strictly on 127.0.0.1 / localhost.
 * Zero external network calls. Pure Node.js built-in http module.
 */

const http = require('http');

const PORT = Number(process.env.PORT || 8787);
const HOST = '127.0.0.1';

function layout(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="en-US">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - PhishGuard Local Simulation</title>
  <style>
    body { font-family: "Poppins", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 760px; margin: 56px auto; padding: 0 20px; background: #0f172a; color: #f8fafc; line-height: 1.6; }
    a { color: #38bdf8; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; margin-right: 6px; }
    .tag-safe { background: #16a34a; color: #fff; }
    .tag-warn { background: #ca8a04; color: #fff; }
    .tag-danger { background: #dc2626; color: #fff; }
    label { display: block; margin-top: 10px; font-size: 13px; color: #cbd5e1; }
    input { width: 100%; padding: 8px 10px; margin-top: 4px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; box-sizing: border-box; }
    button { margin-top: 14px; padding: 9px 14px; border-radius: 6px; border: none; background: #0284c7; color: #fff; font-weight: 600; cursor: pointer; }
    ul { padding-left: 20px; }
    li { margin-bottom: 8px; }
    code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  </style>
</head>
<body>
  <p><a href="/">&larr; Back to Simulation Scenarios</a></p>
  ${bodyHtml}
</body>
</html>`;
}

const ROUTES = {
  '/': () => ({
    status: 200,
    html: layout('Simulation Dashboard', `
      <div class="card">
        <h1>PhishGuard Local &mdash; Localhost Simulation Lab</h1>
        <p>Isolated test pages for safely verifying <strong>PhishGuard Local</strong> detection rules on your local machine (<code>http://localhost:${PORT}</code>).</p>
      </div>
      <div class="card">
        <h2>Test Scenarios</h2>
        <ul>
          <li><span class="tag tag-safe">SAFE</span> <a href="/safe">Normal Page (No Login Forms / No Anomalies)</a></li>
          <li><span class="tag tag-warn">CAUTION</span> <a href="/login-http">Unencrypted HTTP Login Form</a></li>
          <li><span class="tag tag-danger">HIGH RISK</span> <a href="/login-external">Login Form Submitting to Suspicious External Domain</a></li>
          <li><span class="tag tag-danger">HIGH RISK</span> <a href="/login-raw-ip">Login Form Submitting to Raw IP Address</a></li>
          <li><span class="tag tag-warn">CAUTION</span> <a href="/deceptive-links">Page with Deceptive Mismatched Links</a></li>
          <li><span class="tag tag-warn">CAUTION</span> <a href="/redirect-1">Consecutive Redirect Chain Simulation (4 Hops)</a></li>
        </ul>
      </div>
    `)
  }),

  '/safe': () => ({
    status: 200,
    html: layout('Safe Page', `
      <div class="card">
        <span class="tag tag-safe">SAFE SIMULATION</span>
        <h1>Cybersecurity Awareness Article</h1>
        <p>This page contains no suspicious credential forms, no deceptive links, and is not a typosquatted domain.</p>
        <p>PhishGuard Local should display <strong>Green (Safe)</strong>.</p>
      </div>
    `)
  }),

  '/login-http': () => ({
    status: 200,
    html: layout('HTTP Login Form', `
      <div class="card">
        <span class="tag tag-warn">CAUTION SIMULATION</span>
        <h1>Local Portal Login (Unencrypted HTTP)</h1>
        <p>This form contains a password field and submits credentials over unencrypted <code>http://</code>.</p>
        <form action="http://localhost:${PORT}/submitted" method="POST">
          <label>Username <input type="text" name="user" placeholder="demo_user"></label>
          <label>Password <input type="password" name="pass" placeholder="simulation only"></label>
          <button type="submit">Sign In (Simulation)</button>
        </form>
      </div>
    `)
  }),

  '/login-external': () => ({
    status: 200,
    html: layout('External Domain Login Form', `
      <div class="card">
        <span class="tag tag-danger">HIGH RISK SIMULATION</span>
        <h1>Phishing Simulation: External Form Action</h1>
        <p>This page is hosted on <code>localhost</code>, but the form <code>action</code> targets an external domain <code>https://evil-collector.example/capture</code>.</p>
        <form action="https://evil-collector.example/capture" method="POST">
          <label>Email <input type="email" name="email" placeholder="user@example.com"></label>
          <label>Password <input type="password" name="password" placeholder="do not enter real passwords"></label>
          <button type="button" onclick="alert('Isolated simulation - no data submitted')">Submit (Disabled)</button>
        </form>
      </div>
    `)
  }),

  '/login-raw-ip': () => ({
    status: 200,
    html: layout('Raw IP Login Form', `
      <div class="card">
        <span class="tag tag-danger">HIGH RISK SIMULATION</span>
        <h1>Phishing Simulation: Form Action to Raw IP Address</h1>
        <p>This login form points directly to a raw IP address <code>http://192.168.1.99/steal-cred</code>.</p>
        <form action="http://192.168.1.99/steal-cred" method="POST">
          <label>Account <input type="text" name="account" placeholder="demo"></label>
          <label>PIN / Password <input type="password" name="secret" placeholder="simulation"></label>
          <button type="button" onclick="alert('Isolated simulation - no data submitted')">Verify (Disabled)</button>
        </form>
      </div>
    `)
  }),

  '/deceptive-links': () => ({
    status: 200,
    html: layout('Deceptive Links', `
      <div class="card">
        <span class="tag tag-warn">CAUTION SIMULATION</span>
        <h1>Deceptive Links Simulation (Mismatched Anchor URLs)</h1>
        <p>The links below display trusted brand URLs in their visible text, while their <code>href</code> targets point to completely different domains:</p>
        <p><a href="https://malicious-tracker.example/verify">https://paypal.com/verify-account</a></p>
        <p><a href="https://fake-bank.example/login">https://klikbca.com/login</a></p>
      </div>
    `)
  }),

  '/redirect-1': () => ({ status: 302, location: '/redirect-2' }),
  '/redirect-2': () => ({ status: 302, location: '/redirect-3' }),
  '/redirect-3': () => ({ status: 302, location: '/redirect-4' }),
  '/redirect-4': () => ({ status: 302, location: '/redirect-landing' }),

  '/redirect-landing': () => ({
    status: 200,
    html: layout('Redirect Chain Landing', `
      <div class="card">
        <span class="tag tag-warn">REDIRECT CHAIN SIMULATION</span>
        <h1>Landing Page After 4 Consecutive Redirects</h1>
        <p>You passed through the redirect chain: <code>/redirect-1 &rarr; /redirect-2 &rarr; /redirect-3 &rarr; /redirect-4 &rarr; /redirect-landing</code>.</p>
        <p>Open the PhishGuard Local popup to inspect the recorded redirect chain.</p>
      </div>
    `)
  }),

  '/submitted': () => ({
    status: 200,
    html: layout('Simulation Complete', `
      <div class="card">
        <h1>Local Submission Simulation</h1>
        <p>No data was stored or transmitted outside your local device.</p>
      </div>
    `)
  })
};

function createServer() {
  return http.createServer((req, res) => {
    const reqUrl = new URL(req.url, `http://${HOST}:${PORT}`);
    const handler = ROUTES[reqUrl.pathname];

    if (!handler) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 - Scenario not found');
      return;
    }

    const result = handler();
    if (result.status === 302) {
      res.writeHead(302, { Location: result.location });
      res.end();
      return;
    }

    res.writeHead(result.status, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(result.html);
  });
}

if (require.main === module) {
  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`PhishGuard Local Mock Server running at http://localhost:${PORT}`);
    console.log('Press Ctrl+C to stop the server.');
  });
}

module.exports = { createServer, ROUTES };
