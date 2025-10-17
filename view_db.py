#!/usr/bin/env python3
"""
Quick SQLite database viewer - opens a web interface to browse your database.

Usage: python view_db.py
Then open: http://localhost:8001
"""

import sqlite3
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

DB_PATH = "dev.db"

class DBViewerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == '/':
            # Serve main HTML page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>SQLite Viewer</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                    h1 { color: #333; }
                    .query-box { margin: 20px 0; }
                    textarea { width: 100%; height: 100px; font-family: monospace; padding: 10px; }
                    button { padding: 10px 20px; background: #667eea; color: white; border: none; cursor: pointer; font-size: 16px; }
                    button:hover { background: #5568d3; }
                    table { border-collapse: collapse; width: 100%; background: white; margin-top: 20px; }
                    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                    th { background: #667eea; color: white; }
                    tr:nth-child(even) { background: #f9f9f9; }
                    .quick-queries { margin: 20px 0; }
                    .quick-queries button { margin: 5px; background: #4CAF50; }
                </style>
            </head>
            <body>
                <h1>🗄️ SQLite Database Viewer</h1>
                <p><strong>Database:</strong> dev.db</p>

                <div class="quick-queries">
                    <h3>Quick Queries:</h3>
                    <button onclick="runQuery('SELECT * FROM users')">View All Users</button>
                    <button onclick="runQuery('SELECT * FROM refresh_tokens')">View All Tokens</button>
                    <button onclick="runQuery('.tables')">List Tables</button>
                    <button onclick="runQuery('.schema users')">Users Schema</button>
                </div>

                <div class="query-box">
                    <h3>Custom SQL Query:</h3>
                    <textarea id="query" placeholder="Enter SQL query...">SELECT * FROM users;</textarea>
                    <button onclick="runCustomQuery()">Execute Query</button>
                </div>

                <div id="result"></div>

                <script>
                    function runQuery(query) {
                        document.getElementById('query').value = query;
                        runCustomQuery();
                    }

                    async function runCustomQuery() {
                        const query = document.getElementById('query').value;
                        const response = await fetch('/query?q=' + encodeURIComponent(query));
                        const data = await response.json();

                        const resultDiv = document.getElementById('result');

                        if (data.error) {
                            resultDiv.innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
                            return;
                        }

                        if (data.type === 'pragma') {
                            resultDiv.innerHTML = '<pre>' + data.result + '</pre>';
                            return;
                        }

                        if (!data.rows || data.rows.length === 0) {
                            resultDiv.innerHTML = '<p>No results.</p>';
                            return;
                        }

                        let html = '<table><thead><tr>';
                        data.columns.forEach(col => {
                            html += '<th>' + col + '</th>';
                        });
                        html += '</tr></thead><tbody>';

                        data.rows.forEach(row => {
                            html += '<tr>';
                            row.forEach(cell => {
                                html += '<td>' + (cell !== null ? cell : '<em>NULL</em>') + '</td>';
                            });
                            html += '</tr>';
                        });
                        html += '</tbody></table>';

                        resultDiv.innerHTML = html;
                    }

                    // Run default query on load
                    window.onload = () => runQuery('SELECT * FROM users');
                </script>
            </body>
            </html>
            """
            self.wfile.write(html.encode())

        elif parsed_path.path == '/query':
            # Execute SQL query
            params = parse_qs(parsed_path.query)
            query = params.get('q', [''])[0]

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()

                # Handle SQLite special commands
                if query.strip().startswith('.'):
                    if query.strip() == '.tables':
                        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                        tables = [row[0] for row in cursor.fetchall()]
                        result = {'type': 'pragma', 'result': '\n'.join(tables)}
                    elif query.strip().startswith('.schema'):
                        table = query.split()[1] if len(query.split()) > 1 else ''
                        cursor.execute(f"SELECT sql FROM sqlite_master WHERE name='{table}'")
                        schema = cursor.fetchone()
                        result = {'type': 'pragma', 'result': schema[0] if schema else 'Table not found'}
                    else:
                        result = {'error': 'Unsupported command'}
                else:
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description] if cursor.description else []
                    result = {'columns': columns, 'rows': rows}

                conn.close()
                self.wfile.write(json.dumps(result).encode())

            except Exception as e:
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    print("🚀 Starting SQLite Database Viewer...")
    print("📂 Database: dev.db")
    print("🌐 Open in browser: http://localhost:8001")
    print("⏹️  Press Ctrl+C to stop")

    server = HTTPServer(('localhost', 8001), DBViewerHandler)
    server.serve_forever()

