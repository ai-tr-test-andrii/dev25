/**
 * Security tests for Stored XSS remediation in index.ejs
 *
 * These tests verify that todo content stored in the database is rendered
 * with HTML escaping (using EJS <%= %>) rather than unescaped (using EJS <%- %>),
 * preventing Stored XSS attacks (CWE-79).
 *
 * The vulnerability was: <%- marked(new String(todo.content)) %>
 * The fix is:            <%= todo.content %>
 *
 * Tests use the 'ejs' module directly to render the template and assert
 * that XSS payloads are properly escaped in the output.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Load ejs for rendering the template under test
let ejs;
try {
  ejs = require('ejs');
} catch (e) {
  // ejs is a project dependency; this block exists only as a guard
  throw new Error('ejs module not found. Run npm install.');
}

// Path to the template under test
const TEMPLATE_PATH = path.join(__dirname, '..', 'views', 'index.ejs');

/**
 * Minimal EJS render helper that bypasses the ejs-locals layout mechanism.
 * We strip the layout directive so the template body renders standalone.
 */
function renderIndex(todos) {
  let templateSrc = fs.readFileSync(TEMPLATE_PATH, 'utf8');

  // Remove the layout() call so the template renders without an outer layout file
  templateSrc = templateSrc.replace(/<% layout\([^)]*\) -%>\n?/, '');

  return ejs.render(templateSrc, {
    title: 'Test TODO',
    todos: todos,
    // provide a stub for marked() in case it is still referenced
    marked: function(str) { return String(str); },
  });
}

describe('Stored XSS remediation – index.ejs todo content rendering', function () {

  // ── Positive / functionality tests ──────────────────────────────────────────

  test('renders plain todo content correctly', function () {
    const todos = [
      { _id: '507f1f77bcf86cd799439011', content: 'Buy groceries', updated_at: Date.now() }
    ];
    const html = renderIndex(todos);
    assert.ok(html.includes('Buy groceries'), 'Plain text content should appear in output');
  });

  test('renders multiple todo items', function () {
    const todos = [
      { _id: '507f1f77bcf86cd799439011', content: 'First task', updated_at: Date.now() },
      { _id: '507f1f77bcf86cd799439012', content: 'Second task', updated_at: Date.now() },
    ];
    const html = renderIndex(todos);
    assert.ok(html.includes('First task'), 'First todo should be rendered');
    assert.ok(html.includes('Second task'), 'Second todo should be rendered');
  });

  test('renders todo IDs in edit and delete links', function () {
    const id = '507f1f77bcf86cd799439013';
    const todos = [{ _id: id, content: 'Test item', updated_at: Date.now() }];
    const html = renderIndex(todos);
    assert.ok(html.includes(`/edit/${id}`), 'Edit link should contain the todo ID');
    assert.ok(html.includes(`/destroy/${id}`), 'Destroy link should contain the todo ID');
  });

  test('renders empty todo list without error', function () {
    const html = renderIndex([]);
    assert.ok(typeof html === 'string', 'Should render an empty list as a string');
    assert.ok(html.includes('id="list"'), 'Should still contain the list container');
  });

  // ── Security / XSS prevention tests ─────────────────────────────────────────

  test('escapes <script> tag in todo content (basic XSS payload)', function () {
    const xssPayload = '<script>alert("xss")</script>';
    const todos = [
      { _id: '507f1f77bcf86cd799439020', content: xssPayload, updated_at: Date.now() }
    ];
    const html = renderIndex(todos);

    // The raw <script> tag must NOT appear in the output
    assert.ok(
      !html.includes('<script>alert("xss")</script>'),
      'Raw <script> tag must not be present in rendered HTML'
    );
    // The escaped form must appear instead
    assert.ok(
      html.includes('&lt;script&gt;'),
      'Opening <script> tag must be HTML-escaped to &lt;script&gt;'
    );
    assert.ok(
      html.includes('&lt;/script&gt;'),
      'Closing </script> tag must be HTML-escaped to &lt;/script&gt;'
    );
  });

  test('escapes event-handler injection payload (onerror attribute)', function () {
    const xssPayload = '<img src=x onerror="alert(1)">';
    const todos = [
      { _id: '507f1f77bcf86cd799439021', content: xssPayload, updated_at: Date.now() }
    ];
    const html = renderIndex(todos);

    assert.ok(
      !html.includes('<img src=x onerror='),
      'Raw <img> with onerror must not be present in rendered HTML'
    );
    assert.ok(
      html.includes('&lt;img'),
      '<img tag must be HTML-escaped'
    );
  });

  test('escapes SVG-based XSS payload', function () {
    const xssPayload = '<svg onload="alert(document.cookie)">';
    const todos = [
      { _id: '507f1f77bcf86cd799439022', content: xssPayload, updated_at: Date.now() }
    ];
    const html = renderIndex(todos);

    assert.ok(
      !html.includes('<svg onload='),
      'Raw <svg> with onload must not be present in rendered HTML'
    );
    assert.ok(
      html.includes('&lt;svg'),
      '<svg tag must be HTML-escaped'
    );
  });

  test('escapes javascript: URI payload', function () {
    const xssPayload = '<a href="javascript:alert(1)">click</a>';
    const todos = [
      { _id: '507f1f77bcf86cd799439023', content: xssPayload, updated_at: Date.now() }
    ];
    const html = renderIndex(todos);

    assert.ok(
      !html.includes('<a href="javascript:'),
      'Raw javascript: URI anchor must not be present in rendered HTML'
    );
  });

  test('escapes double-quote characters to prevent attribute break-out', function () {
    const xssPayload = '" onmouseover="alert(1)';
    const todos = [
      { _id: '507f1f77bcf86cd799439024', content: xssPayload, updated_at: Date.now() }
    ];
    const html = renderIndex(todos);

    // EJS <%= %> escapes " as &quot;
    assert.ok(
      !html.includes('" onmouseover="alert(1)'),
      'Unescaped double-quote attribute injection must not appear in output'
    );
  });

  test('escapes HTML entities in todo content', function () {
    const content = '<b>bold</b> & "quoted"';
    const todos = [
      { _id: '507f1f77bcf86cd799439025', content: content, updated_at: Date.now() }
    ];
    const html = renderIndex(todos);

    // None of the raw HTML characters should appear unescaped
    assert.ok(!html.includes('<b>bold</b>'), 'Raw <b> tag must be escaped');
    assert.ok(html.includes('&lt;b&gt;'), 'Opening <b> must be escaped to &lt;b&gt;');
  });

  // ── Template source inspection ────────────────────────────────────────────────

  test('template source does not use unescaped <%- output tag for todo.content', function () {
    const templateSrc = fs.readFileSync(TEMPLATE_PATH, 'utf8');

    // Ensure the template does not use the unescaped sink <%- ... todo.content ... %>
    const unsafeSinkPattern = /<%[-]\s*.*todo\.content/;
    assert.ok(
      !unsafeSinkPattern.test(templateSrc),
      'Template must not use unescaped <%- %> tag to render todo.content'
    );
  });

  test('template source does not use unescaped <%- output tag with marked()', function () {
    const templateSrc = fs.readFileSync(TEMPLATE_PATH, 'utf8');

    // Ensure the template does not pipe todo.content through marked() with unescaped output
    const unsafeMarkedPattern = /<%[-]\s*marked\s*\(/;
    assert.ok(
      !unsafeMarkedPattern.test(templateSrc),
      'Template must not use <%- marked(...) %> to render user-supplied content'
    );
  });

  test('template uses escaped <%= tag for todo.content rendering', function () {
    const templateSrc = fs.readFileSync(TEMPLATE_PATH, 'utf8');

    // The safe output tag should be used for todo.content
    const safePattern = /<%=\s*todo\.content\s*%>/;
    assert.ok(
      safePattern.test(templateSrc),
      'Template must use escaped <%= todo.content %> to render todo content safely'
    );
  });
});
