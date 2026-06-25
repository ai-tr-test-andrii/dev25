/**
 * Tests for Stored XSS remediation in EJS templates.
 *
 * CWE-79: Improper Neutralization of Input During Web Page Generation
 *
 * These tests verify that:
 *   1. views/index.ejs renders todo content with HTML escaping (using <%= %>)
 *      instead of the previously vulnerable unescaped sink (<%- marked(...) %>).
 *   2. views/admin.ejs renders the redirectPage query parameter with HTML escaping
 *      (using <%= %>) instead of the previously vulnerable unescaped sink (<%- %>).
 *
 * Both fixes replace the EJS unescaped output tag `<%-` with the HTML-escaped
 * output tag `<%=`, which is the EJS-native, SAST-recognized sanitizer for XSS.
 */

'use strict';

const tap = require('tap');
const ejs = require('ejs');
const path = require('path');
const fs = require('fs');

const VIEWS_DIR = path.join(__dirname, '..', 'views');

// ---------------------------------------------------------------------------
// Helper: read a template file synchronously
// ---------------------------------------------------------------------------
function readTemplate(name) {
  return fs.readFileSync(path.join(VIEWS_DIR, name), 'utf8');
}

// ---------------------------------------------------------------------------
// Helper: render an EJS snippet (not a full layout — strip layout() call)
// ---------------------------------------------------------------------------
function renderEjsSnippet(templateContent, locals) {
  // Remove the layout() directive which requires ejs-locals middleware;
  // we only test the inner HTML rendering here.
  const stripped = templateContent.replace(/<% layout\(.*?\) -%>\n?/g, '');
  return ejs.render(stripped, locals, { rmWhitespace: false });
}

// ===========================================================================
// 1.  views/index.ejs — Stored XSS via todo.content
// ===========================================================================
tap.test('index.ejs — todo content is HTML-escaped (no raw sink)', (t) => {
  const template = readTemplate('index.ejs');

  // Verify the template no longer contains the vulnerable unescaped sink.
  t.notMatch(
    template,
    /<%- marked\(/,
    'Template must not use <%- marked(...) %> unescaped output'
  );

  // Verify the template uses the safe escaped output tag for todo.content.
  t.match(
    template,
    /<%= todo\.content %>/,
    'Template must use <%= todo.content %> for HTML-escaped output'
  );

  t.end();
});

tap.test('index.ejs — XSS payload in stored todo is neutralised', (t) => {
  const template = readTemplate('index.ejs');

  const xssPayload = '<script>alert("xss")</script>';
  const todos = [
    { _id: '507f1f77bcf86cd799439011', content: xssPayload }
  ];

  const rendered = renderEjsSnippet(template, { title: 'Test', todos });

  // The raw script tag must NOT appear in the rendered output.
  t.notOk(
    rendered.includes('<script>alert("xss")</script>'),
    'Raw <script> tag must not appear in rendered output'
  );

  // The payload should appear in its HTML-encoded form.
  t.ok(
    rendered.includes('&lt;script&gt;'),
    'Script tag must be HTML-encoded as &lt;script&gt;'
  );

  t.end();
});

tap.test('index.ejs — HTML attribute injection via todo.content is escaped', (t) => {
  const template = readTemplate('index.ejs');

  // An attacker might try to break out of an attribute context.
  const attrPayload = '" onmouseover="alert(1)';
  const todos = [
    { _id: '507f1f77bcf86cd799439012', content: attrPayload }
  ];

  const rendered = renderEjsSnippet(template, { title: 'Test', todos });

  // The raw quote that would break attribute context must be encoded.
  t.notOk(
    rendered.includes('" onmouseover="alert(1)'),
    'Attribute injection payload must be escaped'
  );

  t.end();
});

tap.test('index.ejs — normal todo content is rendered correctly', (t) => {
  const template = readTemplate('index.ejs');

  const safeContent = 'Buy milk and eggs';
  const todos = [
    { _id: '507f1f77bcf86cd799439013', content: safeContent }
  ];

  const rendered = renderEjsSnippet(template, { title: 'Test', todos });

  t.ok(
    rendered.includes(safeContent),
    'Safe todo content must appear in rendered output unchanged'
  );

  t.end();
});

// ===========================================================================
// 2.  views/admin.ejs — XSS via redirectPage query parameter
// ===========================================================================
tap.test('admin.ejs — redirectPage is HTML-escaped (no raw sink)', (t) => {
  const template = readTemplate('admin.ejs');

  // Verify the template no longer contains the vulnerable unescaped sink.
  t.notMatch(
    template,
    /<%- redirectPage %>/,
    'Template must not use <%- redirectPage %> unescaped output'
  );

  // Verify the template uses the safe escaped output tag.
  t.match(
    template,
    /<%= redirectPage %>/,
    'Template must use <%= redirectPage %> for HTML-escaped output'
  );

  t.end();
});

tap.test('admin.ejs — XSS payload in redirectPage is neutralised', (t) => {
  const template = readTemplate('admin.ejs');

  // Attacker crafts a redirectPage that breaks out of the hidden input value.
  const xssPayload = '"/><script>alert("xss")</script>';

  const rendered = renderEjsSnippet(template, {
    title: 'Admin Access',
    granted: false,
    redirectPage: xssPayload
  });

  // The raw script tag must NOT appear in the rendered output.
  t.notOk(
    rendered.includes('<script>alert("xss")</script>'),
    'Raw <script> tag must not appear in rendered output'
  );

  // The payload should appear in its HTML-encoded form.
  t.ok(
    rendered.includes('&lt;script&gt;'),
    'Script opening tag must be HTML-encoded as &lt;script&gt;'
  );

  t.end();
});

tap.test('admin.ejs — attribute-breaking quote in redirectPage is escaped', (t) => {
  const template = readTemplate('admin.ejs');

  // An attacker attempts to break the value attribute and inject an event handler.
  const attrPayload = '" onfocus="alert(1)" autofocus="';

  const rendered = renderEjsSnippet(template, {
    title: 'Admin Access',
    granted: false,
    redirectPage: attrPayload
  });

  // The raw double-quote that would break the attribute context must be encoded.
  t.notOk(
    rendered.includes(attrPayload),
    'Attribute injection payload must not appear verbatim in rendered output'
  );

  // The double quote must be encoded as &quot;
  t.ok(
    rendered.includes('&quot;'),
    'Double quote must be encoded as &quot; in HTML attribute context'
  );

  t.end();
});

tap.test('admin.ejs — safe redirectPage renders correctly', (t) => {
  const template = readTemplate('admin.ejs');

  const safeRedirect = '/dashboard';

  const rendered = renderEjsSnippet(template, {
    title: 'Admin Access',
    granted: false,
    redirectPage: safeRedirect
  });

  t.ok(
    rendered.includes(safeRedirect),
    'Safe redirectPage value must appear in rendered output unchanged'
  );

  t.end();
});

tap.test('admin.ejs — undefined redirectPage does not throw', (t) => {
  const template = readTemplate('admin.ejs');

  t.doesNotThrow(() => {
    renderEjsSnippet(template, {
      title: 'Admin Access',
      granted: false,
      redirectPage: undefined
    });
  }, 'Rendering with undefined redirectPage must not throw');

  t.end();
});
