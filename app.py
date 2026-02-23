# working code start

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
#         entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/api/vulnerabilities/<int:vuln_id>')
# @login_required
# def api_vulnerability_detail(vuln_id):
#     """Return a single vulnerability by 1-based id."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     entry = dict(vulnerabilities_store[idx])
#     entry['id'] = vuln_id
#     # Use display status if it has been toggled
#     if entry.get('_fixed'):
#         entry['_display_status'] = 'Fixed'
#     else:
#         entry['_display_status'] = entry.get('Status', 'Open')
#     return jsonify({'status': 'success', 'vulnerability': entry})


# @app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
# @login_required
# def api_vulnerability_fix(vuln_id):
#     """Toggle fixed/unfixed on a vulnerability."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     v = vulnerabilities_store[idx]
#     if v.get('_fixed'):
#         v['_fixed'] = False
#         new_status = v.get('Status', 'Open')
#     else:
#         v['_fixed'] = True
#         new_status = 'Fixed'
#     return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)

# working code end

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = i + 1
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)



# working code start

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
#         entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# @app.route('/api/reset-scan', methods=['POST'])
# @login_required
# def api_reset_scan():
#     """Clear scan results and logs so the scanning page starts fresh."""
#     if not active_scan['running']:
#         scan_results.clear()
#         active_scan['logs'] = []
#         active_scan['target'] = ''
#     return jsonify({'status': 'ok', 'running': active_scan['running']})


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/api/vulnerabilities/<int:vuln_id>')
# @login_required
# def api_vulnerability_detail(vuln_id):
#     """Return a single vulnerability by 1-based id."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     entry = dict(vulnerabilities_store[idx])
#     entry['id'] = vuln_id
#     # Use display status if it has been toggled
#     if entry.get('_fixed'):
#         entry['_display_status'] = 'Fixed'
#     else:
#         entry['_display_status'] = entry.get('Status', 'Open')
#     return jsonify({'status': 'success', 'vulnerability': entry})


# @app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
# @login_required
# def api_vulnerability_fix(vuln_id):
#     """Toggle fixed/unfixed on a vulnerability."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     v = vulnerabilities_store[idx]
#     if v.get('_fixed'):
#         v['_fixed'] = False
#         new_status = v.get('Status', 'Open')
#     else:
#         v['_fixed'] = True
#         new_status = 'Fixed'
#     return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# working code end


# working code start

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
#         entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/api/vulnerabilities/<int:vuln_id>')
# @login_required
# def api_vulnerability_detail(vuln_id):
#     """Return a single vulnerability by 1-based id."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     entry = dict(vulnerabilities_store[idx])
#     entry['id'] = vuln_id
#     # Use display status if it has been toggled
#     if entry.get('_fixed'):
#         entry['_display_status'] = 'Fixed'
#     else:
#         entry['_display_status'] = entry.get('Status', 'Open')
#     return jsonify({'status': 'success', 'vulnerability': entry})


# @app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
# @login_required
# def api_vulnerability_fix(vuln_id):
#     """Toggle fixed/unfixed on a vulnerability."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     v = vulnerabilities_store[idx]
#     if v.get('_fixed'):
#         v['_fixed'] = False
#         new_status = v.get('Status', 'Open')
#     else:
#         v['_fixed'] = True
#         new_status = 'Fixed'
#     return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)

# working code end

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = i + 1
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# working code start

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
#         entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/api/vulnerabilities/<int:vuln_id>')
# @login_required
# def api_vulnerability_detail(vuln_id):
#     """Return a single vulnerability by 1-based id."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     entry = dict(vulnerabilities_store[idx])
#     entry['id'] = vuln_id
#     # Use display status if it has been toggled
#     if entry.get('_fixed'):
#         entry['_display_status'] = 'Fixed'
#     else:
#         entry['_display_status'] = entry.get('Status', 'Open')
#     return jsonify({'status': 'success', 'vulnerability': entry})


# @app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
# @login_required
# def api_vulnerability_fix(vuln_id):
#     """Toggle fixed/unfixed on a vulnerability."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     v = vulnerabilities_store[idx]
#     if v.get('_fixed'):
#         v['_fixed'] = False
#         new_status = v.get('Status', 'Open')
#     else:
#         v['_fixed'] = True
#         new_status = 'Fixed'
#     return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)

# working code end

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = i + 1
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)



# working code start

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
#         entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# @app.route('/api/reset-scan', methods=['POST'])
# @login_required
# def api_reset_scan():
#     """Clear scan results and logs so the scanning page starts fresh."""
#     if not active_scan['running']:
#         scan_results.clear()
#         active_scan['logs'] = []
#         active_scan['target'] = ''
#     return jsonify({'status': 'ok', 'running': active_scan['running']})


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/api/vulnerabilities/<int:vuln_id>')
# @login_required
# def api_vulnerability_detail(vuln_id):
#     """Return a single vulnerability by 1-based id."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     entry = dict(vulnerabilities_store[idx])
#     entry['id'] = vuln_id
#     # Use display status if it has been toggled
#     if entry.get('_fixed'):
#         entry['_display_status'] = 'Fixed'
#     else:
#         entry['_display_status'] = entry.get('Status', 'Open')
#     return jsonify({'status': 'success', 'vulnerability': entry})


# @app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
# @login_required
# def api_vulnerability_fix(vuln_id):
#     """Toggle fixed/unfixed on a vulnerability."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     v = vulnerabilities_store[idx]
#     if v.get('_fixed'):
#         v['_fixed'] = False
#         new_status = v.get('Status', 'Open')
#     else:
#         v['_fixed'] = True
#         new_status = 'Fixed'
#     return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# working code end


# working code start

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
#         entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/api/vulnerabilities/<int:vuln_id>')
# @login_required
# def api_vulnerability_detail(vuln_id):
#     """Return a single vulnerability by 1-based id."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     entry = dict(vulnerabilities_store[idx])
#     entry['id'] = vuln_id
#     # Use display status if it has been toggled
#     if entry.get('_fixed'):
#         entry['_display_status'] = 'Fixed'
#     else:
#         entry['_display_status'] = entry.get('Status', 'Open')
#     return jsonify({'status': 'success', 'vulnerability': entry})


# @app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
# @login_required
# def api_vulnerability_fix(vuln_id):
#     """Toggle fixed/unfixed on a vulnerability."""
#     idx = vuln_id - 1
#     if idx < 0 or idx >= len(vulnerabilities_store):
#         return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
#     v = vulnerabilities_store[idx]
#     if v.get('_fixed'):
#         v['_fixed'] = False
#         new_status = v.get('Status', 'Open')
#     else:
#         v['_fixed'] = True
#         new_status = 'Fixed'
#     return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)

# working code end

# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime
# from vapt_auto import perform_vapt_scan

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # ─────────────────────────────────────────────
# #  LIVE DATA STORE  (in-memory, persists per run)
# # ─────────────────────────────────────────────
# # Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
# targets_store = {}
# targets_counter = [0]

# # All vulnerabilities from every scan
# vulnerabilities_store = []

# # Reports: list of report metadata dicts
# reports_store = []
# reports_counter = [0]

# # Dashboard stats (recomputed after each scan)
# dashboard_stats = {
#     'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
# }

# # Scan engine state
# scan_results = {}
# auth_sessions = {}
# update_queue = queue.Queue()
# active_scan = {'running': False, 'target': '', 'logs': []}


# # ─────────────────────────────────────────────
# #  HELPERS
# # ─────────────────────────────────────────────

# def login_required(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated


# def severity_counts(vuln_list):
#     c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
#     for v in vuln_list:
#         sev = v.get('Severity', '').lower()
#         if sev in c:
#             c[sev] += 1
#     return c


# def rebuild_dashboard_stats():
#     global dashboard_stats
#     sc = severity_counts(vulnerabilities_store)
#     dashboard_stats = {
#         'total': len(vulnerabilities_store),
#         'critical': sc['critical'],
#         'high': sc['high'],
#         'medium': sc['medium'],
#         'low': sc['low'],
#     }


# def log(msg):
#     ts = datetime.now().strftime('%H:%M:%S')
#     line = f"[{ts}] {msg}"
#     active_scan['logs'].append(line)
#     update_queue.put({'type': 'log', 'message': line})


# def get_or_create_target(url):
#     for tid, t in targets_store.items():
#         if t['url'] == url:
#             return tid
#     targets_counter[0] += 1
#     tid = targets_counter[0]
#     if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
#         ttype = 'API'
#     elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
#         ttype = 'IP'
#     else:
#         ttype = 'Web'
#     name = url.replace('https://', '').replace('http://', '').split('/')[0]
#     targets_store[tid] = {
#         'id': tid,
#         'name': name,
#         'url': url,
#         'type': ttype,
#         'status': 'Active',
#         'last_scan': 'Never',
#         'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
#     }
#     return tid


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))
#     user = USERS.get(email)
#     if user and check_password_hash(user['password_hash'], password):
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True
#         return redirect(url_for('dashboard'))
#     flash('Invalid email or password. Please try again.', 'error')
#     return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  LIVE DATA API ENDPOINTS
# # ─────────────────────────────────────────────

# @app.route('/api/dashboard-stats')
# @login_required
# def api_dashboard_stats():
#     """Live dashboard statistics."""
#     recent_vulns = vulnerabilities_store[-5:][::-1]
#     recent = [{
#         'test': v.get('Test', ''),
#         'severity': v.get('Severity', ''),
#         'target': v.get('target_url', ''),
#         'status': v.get('Status', ''),
#         'finding': v.get('Finding', ''),
#     } for v in recent_vulns]

#     # Scan overview counts
#     total_scans = len(reports_store)
#     completed = sum(1 for r in reports_store if r['status'] == 'Completed')

#     return jsonify({
#         'stats': dashboard_stats,
#         'recent_vulnerabilities': recent,
#         'total_targets': len(targets_store),
#         'total_reports': total_scans,
#         'completed_scans': completed,
#     })


# @app.route('/api/targets')
# @login_required
# def api_targets():
#     return jsonify({'targets': list(targets_store.values())})


# @app.route('/api/targets', methods=['POST'])
# @login_required
# def api_target_add():
#     data = request.get_json()
#     url = data.get('url', '').strip()
#     name = data.get('name', '').strip()
#     if not url:
#         return jsonify({'status': 'error', 'message': 'URL required'})
#     tid = get_or_create_target(url)
#     if name:
#         targets_store[tid]['name'] = name
#     if data.get('type'):
#         targets_store[tid]['type'] = data['type']
#     return jsonify({'status': 'success', 'target': targets_store[tid]})


# @app.route('/api/targets/<int:target_id>', methods=['DELETE'])
# @login_required
# def api_target_delete(target_id):
#     if target_id in targets_store:
#         del targets_store[target_id]
#         return jsonify({'status': 'success'})
#     return jsonify({'status': 'error', 'message': 'Target not found'})


# @app.route('/api/vulnerabilities')
# @login_required
# def api_vulnerabilities():
#     """Return all live vulnerabilities with optional filters."""
#     severity_filter = request.args.get('severity', '').lower()
#     status_filter = request.args.get('status', '').lower()
#     search = request.args.get('q', '').lower()

#     result = vulnerabilities_store[:]
#     if severity_filter and severity_filter != 'all':
#         result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
#     if status_filter and status_filter not in ('all', ''):
#         result = [v for v in result if v.get('Status', '').lower() == status_filter]
#     if search:
#         result = [v for v in result if
#                   search in v.get('Test', '').lower() or
#                   search in v.get('Finding', '').lower() or
#                   search in v.get('target_url', '').lower()]

#     indexed = []
#     for i, v in enumerate(result):
#         entry = dict(v)
#         entry['id'] = i + 1
#         indexed.append(entry)

#     return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


# @app.route('/api/reports')
# @login_required
# def api_reports():
#     return jsonify({'reports': list(reversed(reports_store))})


# @app.route('/api/scan-logs')
# @login_required
# def api_scan_logs():
#     """Return all accumulated logs for the current or last scan."""
#     return jsonify({
#         'running': active_scan['running'],
#         'target': active_scan['target'],
#         'logs': active_scan['logs'],
#     })


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         req_session = requests.Session()

#         if auth_type == 'form':
#             login_url = auth_data.get('login_url', '').strip()
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             username_field = auth_data.get('username_field', 'username')
#             password_field = auth_data.get('password_field', 'password')
#             success_indicator = auth_data.get('success_indicator', '').strip()

#             if not all([login_url, username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

#             try:
#                 req_session.verify = False
#                 login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
#                 hidden_fields = {}
#                 try:
#                     from bs4 import BeautifulSoup
#                     soup = BeautifulSoup(login_page.text, 'html.parser')
#                     for hidden in soup.find_all('input', {'type': 'hidden'}):
#                         n = hidden.get('name')
#                         v = hidden.get('value')
#                         if n and n not in [username_field, password_field]:
#                             hidden_fields[n] = v
#                 except Exception:
#                     pass

#                 login_data = {username_field: username, password_field: password}
#                 login_data.update(hidden_fields)
#                 login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

#                 failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
#                                     'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
#                 has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                 url_changed = login_response.url != login_url

#                 test_sess = requests.Session()
#                 test_sess.verify = False
#                 wrong_data = login_data.copy()
#                 wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                 wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                 response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                 login_success = False
#                 success_reason = ""
#                 if success_indicator and success_indicator.lower() in login_response.text.lower():
#                     login_success = True
#                     success_reason = f'Found success indicator "{success_indicator}"'
#                 elif url_changed and response_differs:
#                     login_success = True
#                     success_reason = 'Authentication verified (URL changed & responses differ)'
#                 elif url_changed and not has_failure:
#                     login_success = True
#                     success_reason = 'Page changed after login (no errors detected)'
#                 elif response_differs and not has_failure:
#                     login_success = True
#                     success_reason = 'Responses differ (authentication working)'

#                 if login_success:
#                     auth_sessions[target] = {
#                         'type': 'form', 'session': req_session,
#                         'cookies': req_session.cookies.get_dict(),
#                         'login_url': login_url, 'login_data': login_data,
#                     }
#                     return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#         elif auth_type == 'basic':
#             username = auth_data.get('username', '').strip()
#             password = auth_data.get('password', '').strip()
#             if not all([username, password]):
#                 return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
#             try:
#                 resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                 resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                 resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
#                 if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                 elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
#                     auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                     return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                 else:
#                     return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
#             except requests.exceptions.Timeout:
#                 return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#             except Exception as e:
#                 return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
#         else:
#             return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """SSE endpoint — streams log lines and phase events in real time."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data_payload = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data_payload:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data_payload,
#                 'session': auth_sessions.get(target)
#             }

#         # Reset state for new scan
#         active_scan['running'] = True
#         active_scan['target'] = target
#         active_scan['logs'] = []
#         scan_results.clear()

#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 log(f"🚀 Scan started for {target}")
#                 log(f"🔐 Authentication: {auth_type}")

#                 def progress_cb(msg):
#                     """Forward vapt_auto events to SSE queue AND log panel."""
#                     update_queue.put(msg)
#                     if isinstance(msg, dict):
#                         mtype = msg.get('type', '')
#                         if mtype == 'phase':
#                             log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
#                         elif mtype == 'crawling':
#                             log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
#                         elif mtype == 'crawl_complete':
#                             log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
#                         elif mtype == 'crawl_start':
#                             log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=progress_cb
#                 )

#                 if result['status'] == 'success':
#                     raw_results = result['results']
#                     filename = result['filename']

#                     # Tag each finding
#                     for r in raw_results:
#                         r['target_url'] = target
#                         r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

#                     # Add to global vulnerability list
#                     vulnerabilities_store.extend(raw_results)

#                     # Recompute dashboard
#                     rebuild_dashboard_stats()

#                     # Update/create target record
#                     tid = get_or_create_target(target)
#                     sc = severity_counts(raw_results)
#                     targets_store[tid]['last_scan'] = datetime.now().strftime('%Y-%m-%d')
#                     targets_store[tid]['status'] = 'Active'
#                     targets_store[tid]['vuln_counts'] = {
#                         'critical': sc['critical'],
#                         'high': sc['high'],
#                         'medium': sc['medium'],
#                         'low': sc['low'],
#                     }

#                     # Add report record
#                     reports_counter[0] += 1
#                     rid = reports_counter[0]
#                     target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
#                     reports_store.append({
#                         'id': rid,
#                         'name': f"Full Security Scan – {target_name}",
#                         'target_url': target,
#                         'filename': filename,
#                         'date': datetime.now().strftime('%Y-%m-%d'),
#                         'status': 'Completed',
#                         'vuln_counts': {
#                             'critical': sc['critical'],
#                             'high': sc['high'],
#                             'medium': sc['medium'],
#                             'low': sc['low'],
#                         },
#                         'total': len(raw_results),
#                     })

#                     scan_results['last_file'] = filename
#                     scan_results['last_result'] = result

#                     log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
#                     log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
#                 else:
#                     scan_results['last_error'] = result.get('message', 'Unknown error')
#                     log(f"❌ Scan failed: {result.get('message')}")

#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#                 log(f"❌ Error: {str(e)}")
#             finally:
#                 active_scan['running'] = False

#         t = threading.Thread(target=run_scan)
#         t.daemon = True
#         t.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({
#             'status': 'success',
#             'filename': result['filename'],
#             'results': result['results'],
#         })
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# @app.route('/download-report/<int:report_id>')
# @login_required
# def download_report(report_id):
#     """Download a specific historical report by ID."""
#     report = next((r for r in reports_store if r['id'] == report_id), None)
#     if not report:
#         return jsonify({'status': 'error', 'message': 'Report not found'})
#     filename = report['filename']
#     if not os.path.exists(filename):
#         return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
#     return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# # ─────────────────────────────────────────────
# #  RUN
# # ─────────────────────────────────────────────

# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


# from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
# import os
# import requests
# import base64
# from vapt_auto import perform_vapt_scan
# import json
# import queue
# import threading
# from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash

# app = Flask(__name__)
# app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# # ─────────────────────────────────────────────
# #  USER STORE (replace with DB in production)
# #  Only admin@vapt.pro / Admin@1234 is valid.
# #  Any other credentials will be rejected.
# # ─────────────────────────────────────────────
# USERS = {
#     'admin@vapt.pro': {
#         'name': 'Admin User',
#         'password_hash': generate_password_hash('Admin@1234'),
#         'role': 'admin'
#     },
# }

# # Store scan results and authentication sessions
# scan_results = {}
# auth_sessions = {}

# # Queue for real-time updates
# update_queue = queue.Queue()
# active_scan = {'running': False}


# # ─────────────────────────────────────────────
# #  LOGIN REQUIRED DECORATOR
# # ─────────────────────────────────────────────

# def login_required(f):
#     """Decorator to protect routes — redirects to login if not authenticated."""
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_email' not in session:
#             flash('Please sign in to access this page.', 'error')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#     return decorated_function


# # ─────────────────────────────────────────────
# #  AUTH ROUTES
# # ─────────────────────────────────────────────

# @app.route('/')
# def index():
#     """Login page — redirect to dashboard if already logged in."""
#     if 'user_email' in session:
#         return redirect(url_for('dashboard'))
#     return render_template('index.html')


# @app.route('/login', methods=['POST'])
# def login():
#     """Handle login form submission with server-side credential validation."""
#     email = request.form.get('email', '').strip().lower()
#     password = request.form.get('password', '').strip()

#     # Basic input validation
#     if not email or not password:
#         flash('Email and password are required.', 'error')
#         return redirect(url_for('index'))

#     # Look up user
#     user = USERS.get(email)

#     if user and check_password_hash(user['password_hash'], password):
#         # Credentials valid — create session
#         session.clear()
#         session['user_email'] = email
#         session['user_name'] = user['name']
#         session['user_role'] = user['role']
#         session.permanent = True  # session persists across browser restarts
#         return redirect(url_for('dashboard'))
#     else:
#         flash('Invalid email or password. Please try again.', 'error')
#         return redirect(url_for('index'))


# @app.route('/logout')
# def logout():
#     """Clear session and redirect to login."""
#     session.clear()
#     flash('You have been logged out successfully.', 'info')
#     return redirect(url_for('index'))


# @app.route('/forgot-password')
# def forgot_password():
#     """Forgot password page."""
#     return render_template('forgot-password.html')


# @app.route('/check-email')
# def check_email():
#     """Check email confirmation page."""
#     return render_template('check-email.html')


# # ─────────────────────────────────────────────
# #  MAIN APP ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', user_name=session.get('user_name'))


# @app.route('/scanning')
# @login_required
# def scanning():
#     return render_template('scanning.html')


# @app.route('/targets')
# @login_required
# def targets():
#     return render_template('targets.html')


# @app.route('/targets/create')
# @login_required
# def target_create():
#     return render_template('target-create.html')


# @app.route('/targets/<int:target_id>/view')
# @login_required
# def target_view(target_id):
#     return render_template('target-view.html', target_id=target_id)


# @app.route('/targets/<int:target_id>/edit')
# @login_required
# def target_edit(target_id):
#     return render_template('target-edit.html', target_id=target_id)


# @app.route('/vulnerabilities')
# @login_required
# def vulnerabilities():
#     return render_template('vulnerabilities.html')


# @app.route('/vulnerabilities/<int:vuln_id>')
# @login_required
# def vulnerability_view(vuln_id):
#     return render_template('vulnerability-view.html', vuln_id=vuln_id)


# @app.route('/reports')
# @login_required
# def reports():
#     return render_template('reports.html')


# @app.route('/reports/<int:report_id>')
# @login_required
# def report_view(report_id):
#     return render_template('report-view.html', report_id=report_id)


# @app.route('/features')
# @login_required
# def features():
#     return render_template('features.html')


# @app.route('/documentation')
# @login_required
# def documentation():
#     return render_template('documentation.html')


# @app.route('/about')
# @login_required
# def about():
#     return render_template('about.html')


# @app.route('/settings')
# @login_required
# def settings():
#     return render_template('settings.html')


# # ─────────────────────────────────────────────
# #  VAPT SCAN API ROUTES  (all protected)
# # ─────────────────────────────────────────────

# @app.route('/test-auth', methods=['POST'])
# @login_required
# def test_auth():
#     """Test authentication credentials against a target."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

#         print(f"\n[*] Testing authentication for: {target}")
#         print(f"[*] Auth type: {auth_type}")

#         if not target.startswith(('http://', 'https://')):
#             target = f"http://{target}"

#         session_req = requests.Session()

#         try:
#             if auth_type == 'form':
#                 login_url = auth_data.get('login_url', '').strip()
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 username_field = auth_data.get('username_field', 'username')
#                 password_field = auth_data.get('password_field', 'password')
#                 success_indicator = auth_data.get('success_indicator', '').strip()

#                 if not all([login_url, username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in all required fields (Login URL, Username, Password)'})

#                 try:
#                     session_req.verify = False
#                     login_page = session_req.get(login_url, timeout=15, allow_redirects=True)
#                     hidden_fields = {}

#                     try:
#                         from bs4 import BeautifulSoup
#                         soup = BeautifulSoup(login_page.text, 'html.parser')
#                         csrf_patterns = ['csrf', '_token', 'authenticity', '__requestverification', '_nonce', 'xsrf']
#                         for csrf_pattern in csrf_patterns:
#                             csrf_input = soup.find('input', {'name': lambda x: x and csrf_pattern in x.lower()})
#                             if csrf_input:
#                                 break
#                         for hidden in soup.find_all('input', {'type': 'hidden'}):
#                             name = hidden.get('name')
#                             value = hidden.get('value')
#                             if name and name not in [username_field, password_field]:
#                                 hidden_fields[name] = value
#                     except Exception:
#                         pass

#                     login_data = {username_field: username, password_field: password}
#                     if hidden_fields:
#                         login_data.update(hidden_fields)

#                     login_response = session_req.post(login_url, data=login_data, allow_redirects=True, timeout=15)
#                     failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
#                                         'unauthorized', 'authentication failed', 'login failed']
#                     has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
#                     url_changed = login_response.url != login_url

#                     test_session = requests.Session()
#                     test_session.verify = False
#                     wrong_data = login_data.copy()
#                     wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
#                     wrong_response = test_session.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
#                     response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

#                     login_success = False
#                     success_reason = ""

#                     if success_indicator and success_indicator.lower() in login_response.text.lower():
#                         login_success = True
#                         success_reason = f'Found success indicator "{success_indicator}"'
#                     elif url_changed and response_differs:
#                         login_success = True
#                         success_reason = 'Authentication verified (URL changed & responses differ)'
#                     elif url_changed and not has_failure:
#                         login_success = True
#                         success_reason = 'Page changed after login (no errors detected)'
#                     elif response_differs and not has_failure:
#                         login_success = True
#                         success_reason = 'Responses differ (authentication working)'

#                     if login_success:
#                         auth_sessions[target] = {
#                             'type': 'form', 'session': session_req, 'cookies': session_req.cookies.get_dict(),
#                             'login_url': login_url, 'login_data': login_data,
#                             'username_field': username_field, 'password_field': password_field
#                         }
#                         return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials and field names.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

#             elif auth_type == 'basic':
#                 username = auth_data.get('username', '').strip()
#                 password = auth_data.get('password', '').strip()
#                 if not all([username, password]):
#                     return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})

#                 try:
#                     response_correct = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
#                     response_wrong = requests.get(target, auth=(username, "wrong_password_xyz123"), timeout=15, verify=False, allow_redirects=True)
#                     response_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)

#                     if (response_none.status_code == 401 or response_wrong.status_code == 401) and response_correct.status_code == 200:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
#                     elif response_correct.status_code == 200 and response_correct.text != response_wrong.text:
#                         auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
#                         return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
#                     else:
#                         return jsonify({'status': 'error', 'message': 'Could not verify basic authentication. The endpoint may not require auth.'})

#                 except requests.exceptions.Timeout:
#                     return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
#                 except Exception as e:
#                     return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})

#             else:
#                 return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

#         except requests.exceptions.ConnectionError:
#             return jsonify({'status': 'error', 'message': 'Could not connect to target. Please verify the URL.'})
#         except Exception as e:
#             return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})

#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


# @app.route('/scan-progress')
# @login_required
# def scan_progress():
#     """Server-Sent Events endpoint for real-time scan progress."""
#     def generate():
#         while active_scan['running']:
#             try:
#                 update = update_queue.get(timeout=1)
#                 yield f"data: {json.dumps(update)}\n\n"
#             except queue.Empty:
#                 yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
#         yield f"data: {json.dumps({'type': 'complete'})}\n\n"

#     return Response(generate(), mimetype='text/event-stream')


# @app.route('/scan', methods=['POST'])
# @login_required
# def scan():
#     """Handle scan requests."""
#     try:
#         data = request.get_json()
#         target = data.get('target', '').strip()
#         auth_type = data.get('auth_type', 'none')
#         auth_data = data.get('auth_data', {})
#         owasp_enabled = data.get('owasp_enabled', True)

#         if not target:
#             return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

#         print(f"\n[*] Starting scan for: {target}")

#         auth_credentials = None
#         if auth_type != 'none' and auth_data:
#             auth_credentials = {
#                 'type': auth_type,
#                 'data': auth_data,
#                 'session': auth_sessions.get(target)
#             }

#         active_scan['running'] = True
#         while not update_queue.empty():
#             try:
#                 update_queue.get_nowait()
#             except queue.Empty:
#                 break

#         def run_scan():
#             try:
#                 result = perform_vapt_scan(
#                     target,
#                     auth_credentials=auth_credentials,
#                     owasp_enabled=owasp_enabled,
#                     progress_callback=lambda msg: update_queue.put(msg)
#                 )
#                 if result['status'] == 'success':
#                     scan_results['last_file'] = result['filename']
#                     scan_results['last_result'] = result
#             except Exception as e:
#                 print(f"[!] Scan error: {str(e)}")
#                 scan_results['last_error'] = str(e)
#             finally:
#                 active_scan['running'] = False

#         scan_thread = threading.Thread(target=run_scan)
#         scan_thread.daemon = True
#         scan_thread.start()

#         return jsonify({'status': 'started', 'message': 'Scan started.'})

#     except Exception as e:
#         active_scan['running'] = False
#         return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


# @app.route('/scan-status')
# @login_required
# def scan_status():
#     """Get current scan status and results."""
#     if active_scan['running']:
#         return jsonify({'status': 'running'})
#     elif 'last_result' in scan_results:
#         result = scan_results['last_result']
#         return jsonify({'status': 'success', 'filename': result['filename'], 'results': result['results']})
#     elif 'last_error' in scan_results:
#         return jsonify({'status': 'error', 'message': scan_results['last_error']})
#     else:
#         return jsonify({'status': 'idle'})


# @app.route('/download')
# @login_required
# def download():
#     """Handle report downloads."""
#     try:
#         filename = scan_results.get('last_file')
#         if not filename:
#             return jsonify({'status': 'error', 'message': 'No report available for download'})
#         if not os.path.exists(filename):
#             return jsonify({'status': 'error', 'message': 'Report file not found'})
#         return send_file(filename, as_attachment=True, download_name=filename)
#     except Exception as e:
#         return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


# if __name__ == '__main__':
#     print("=" * 80)
#     print("              ADVANCED VAPT SCANNER PRO")
#     print("          Vulnerability Assessment & Penetration Testing Tool")
#     print("=" * 80)
#     print("\n[+] Server starting...")
#     print("[+] Access the scanner at: http://localhost:5005")
#     print("[+] Login credentials:")
#     print("    admin@vapt.pro  /  Admin@1234")
#     print("[+] Press Ctrl+C to stop\n")
#     print("=" * 80)
#     print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
#     print("=" * 80 + "\n")
#     app.run(debug=True, host='0.0.0.0', port=5005)


from flask import Flask, render_template, request, jsonify, send_file, Response, redirect, url_for, flash, session
import os
import requests
import json
import queue
import threading
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from vapt_auto import perform_vapt_scan

app = Flask(__name__)
app.secret_key = '929465f4cc9c6769c0d77377b820975d19bf0b5cada96422bec0608ebc4e32b5'

# ─────────────────────────────────────────────
#  USER STORE
# ─────────────────────────────────────────────
USERS = {
    'admin@vapt.pro': {
        'name': 'Admin User',
        'password_hash': generate_password_hash('Admin@1234'),
        'role': 'admin'
    },
}

# ─────────────────────────────────────────────
#  LIVE DATA STORE  (in-memory, persists per run)
# ─────────────────────────────────────────────
# Targets: { id -> {id, name, url, type, status, last_scan, vuln_counts} }
targets_store = {}
targets_counter = [0]

# All vulnerabilities from every scan
vulnerabilities_store = []

# Reports: list of report metadata dicts
reports_store = []
reports_counter = [0]

# Dashboard stats (recomputed after each scan)
dashboard_stats = {
    'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0
}

# Scan engine state
scan_results = {}
auth_sessions = {}
update_queue = queue.Queue()
active_scan = {'running': False, 'target': '', 'logs': []}


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_email' not in session:
            flash('Please sign in to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


def severity_counts(vuln_list):
    c = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vuln_list:
        sev = v.get('Severity', '').lower()
        if sev in c:
            c[sev] += 1
    return c


def rebuild_dashboard_stats():
    global dashboard_stats
    sc = severity_counts(vulnerabilities_store)
    dashboard_stats = {
        'total': len(vulnerabilities_store),
        'critical': sc['critical'],
        'high': sc['high'],
        'medium': sc['medium'],
        'low': sc['low'],
    }


def log(msg):
    ts = datetime.now().strftime('%H:%M:%S')
    line = f"[{ts}] {msg}"
    active_scan['logs'].append(line)
    update_queue.put({'type': 'log', 'message': line})


def get_or_create_target(url):
    for tid, t in targets_store.items():
        if t['url'] == url:
            return tid
    targets_counter[0] += 1
    tid = targets_counter[0]
    if any(x in url for x in ['api.', '/api', '/rest', '/graphql']):
        ttype = 'API'
    elif any(url.startswith(p) for p in ['192.168.', '10.', '172.']):
        ttype = 'IP'
    else:
        ttype = 'Web'
    name = url.replace('https://', '').replace('http://', '').split('/')[0]
    targets_store[tid] = {
        'id': tid,
        'name': name,
        'url': url,
        'type': ttype,
        'status': 'Active',
        'last_scan': 'Never',
        'scan_count': 0,
        'scan_history': [],
        'description': '',
        'vuln_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
        'total_vulns': 0,
    }
    return tid


# ─────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    if not email or not password:
        flash('Email and password are required.', 'error')
        return redirect(url_for('index'))
    user = USERS.get(email)
    if user and check_password_hash(user['password_hash'], password):
        session.clear()
        session['user_email'] = email
        session['user_name'] = user['name']
        session['user_role'] = user['role']
        session.permanent = True
        return redirect(url_for('dashboard'))
    flash('Invalid email or password. Please try again.', 'error')
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')


@app.route('/check-email')
def check_email():
    return render_template('check-email.html')


# ─────────────────────────────────────────────
#  MAIN APP ROUTES
# ─────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user_name=session.get('user_name'), stats=dashboard_stats)


@app.route('/scanning')
@login_required
def scanning():
    return render_template('scanning.html')


@app.route('/targets')
@login_required
def targets():
    return render_template('targets.html')


@app.route('/targets/create')
@login_required
def target_create():
    return render_template('target-create.html')


@app.route('/targets/<int:target_id>/view')
@login_required
def target_view(target_id):
    return render_template('target-view.html', target_id=target_id)


@app.route('/targets/<int:target_id>/edit')
@login_required
def target_edit(target_id):
    return render_template('target-edit.html', target_id=target_id)


@app.route('/vulnerabilities')
@login_required
def vulnerabilities():
    return render_template('vulnerabilities.html')


@app.route('/vulnerabilities/<int:vuln_id>')
@login_required
def vulnerability_view(vuln_id):
    return render_template('vulnerability-view.html', vuln_id=vuln_id)


@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')


@app.route('/reports/<int:report_id>')
@login_required
def report_view(report_id):
    return render_template('report-view.html', report_id=report_id)


@app.route('/features')
@login_required
def features():
    return render_template('features.html')


@app.route('/documentation')
@login_required
def documentation():
    return render_template('documentation.html')


@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


# ─────────────────────────────────────────────
#  LIVE DATA API ENDPOINTS
# ─────────────────────────────────────────────

@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    """Live dashboard statistics with enhanced per-scan metrics."""
    recent_vulns = vulnerabilities_store[-5:][::-1]
    recent = [{
        'test': v.get('Test', ''),
        'severity': v.get('Severity', ''),
        'target': v.get('target_url', ''),
        'status': v.get('Status', ''),
        'finding': v.get('Finding', ''),
    } for v in recent_vulns]

    total_scans = len(reports_store)
    completed = sum(1 for r in reports_store if r['status'] == 'Completed')

    # Per-scan enriched history (last 10)
    scan_history = []
    for r in list(reversed(reports_store))[:10]:
        total = r.get('total', 0)
        vc    = r.get('vuln_counts', {})
        crit  = vc.get('critical', 0)
        high  = vc.get('high', 0)
        med   = vc.get('medium', 0)
        low   = vc.get('low', 0)
        safe_count  = med + low + max(0, total - crit - high - med - low)
        success_pct = round((safe_count / total * 100), 1) if total > 0 else 100.0
        vuln_pct    = round(((crit + high) / total * 100), 1) if total > 0 else 0.0
        target_host = r.get('target_url', r.get('name', '')).replace('https://','').replace('http://','').split('/')[0]
        scan_history.append({
            'id':          r.get('id'),
            'name':        r.get('name', ''),
            'target':      target_host,
            'date':        r.get('date', ''),
            'scan_time':   r.get('scan_time', r.get('date', '')),
            'runtime':     r.get('runtime_seconds', None),
            'status':      r.get('status', 'Completed'),
            'total':       total,
            'critical':    crit,
            'high':        high,
            'medium':      med,
            'low':         low,
            'success_pct': success_pct,
            'vuln_pct':    vuln_pct,
        })

    total_vulns = dashboard_stats.get('total', 0)
    def pct(n): return round(n / total_vulns * 100, 1) if total_vulns > 0 else 0
    severity_pct = {
        'critical': pct(dashboard_stats.get('critical', 0)),
        'high':     pct(dashboard_stats.get('high', 0)),
        'medium':   pct(dashboard_stats.get('medium', 0)),
        'low':      pct(dashboard_stats.get('low', 0)),
    }

    bar_labels, bar_high, bar_med, bar_low = [], [], [], []
    for entry in list(reversed(scan_history))[-8:]:
        bar_labels.append(entry['target'][:12] or entry['date'])
        bar_high.append(entry['critical'] + entry['high'])
        bar_med.append(entry['medium'])
        bar_low.append(entry['low'])

    live_scan = {
        'running': active_scan.get('running', False),
        'target':  active_scan.get('target', ''),
    }

    overall_success = round(
        sum(s['success_pct'] for s in scan_history) / len(scan_history), 1
    ) if scan_history else None

    return jsonify({
        'stats':                  dashboard_stats,
        'severity_pct':           severity_pct,
        'recent_vulnerabilities': recent,
        'total_targets':          len(targets_store),
        'total_reports':          total_scans,
        'completed_scans':        completed,
        'scan_history':           scan_history,
        'bar_chart':              {'labels': bar_labels, 'high': bar_high, 'medium': bar_med, 'low': bar_low},
        'live_scan':              live_scan,
        'overall_success_pct':    overall_success,
    })


@app.route('/api/targets')
@login_required
def api_targets():
    return jsonify({'targets': list(targets_store.values())})


@app.route('/api/targets', methods=['POST'])
@login_required
def api_target_add():
    data = request.get_json()
    url = data.get('url', '').strip()
    name = data.get('name', '').strip()
    if not url:
        return jsonify({'status': 'error', 'message': 'URL required'})
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    tid = get_or_create_target(url)
    if name:                        targets_store[tid]['name']        = name
    if data.get('type'):            targets_store[tid]['type']        = data['type']
    if 'description' in data:       targets_store[tid]['description'] = data.get('description','')
    return jsonify({'status': 'success', 'target': targets_store[tid]})


@app.route('/api/targets/<int:target_id>', methods=['GET'])
@login_required
def api_target_get(target_id):
    if target_id in targets_store:
        t = targets_store[target_id]
        # Build recent vulns for this target
        target_vulns = [v for v in vulnerabilities_store if v.get('target_url') == t['url']]
        recent = []
        for v in reversed(target_vulns[-10:]):
            recent.append({
                'test': v.get('Test', ''),
                'severity': v.get('Severity', ''),
                'finding': v.get('Finding', ''),
                'status': v.get('Status', ''),
                'path': v.get('Vulnerable Path', ''),
                'id': vulnerabilities_store.index(v) + 1,
            })
        result = dict(t)
        result['recent_vulns'] = recent
        return jsonify({'status': 'ok', 'target': result})
    return jsonify({'status': 'error', 'message': 'Target not found'})


@app.route('/api/targets/<int:target_id>', methods=['PUT'])
@login_required
def api_target_update(target_id):
    if target_id not in targets_store:
        return jsonify({'status': 'error', 'message': 'Target not found'})
    data = request.get_json()
    t = targets_store[target_id]
    if data.get('name'):        t['name'] = data['name']
    if data.get('url'):         t['url']  = data['url']
    if data.get('type'):        t['type'] = data['type']
    if 'description' in data:   t['description'] = data['description']
    return jsonify({'status': 'success', 'target': t})


@app.route('/api/targets/<int:target_id>', methods=['DELETE'])
@login_required
def api_target_delete(target_id):
    if target_id in targets_store:
        del targets_store[target_id]
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Target not found'})


@app.route('/api/vulnerabilities')
@login_required
def api_vulnerabilities():
    """Return all live vulnerabilities with optional filters."""
    severity_filter = request.args.get('severity', '').lower()
    status_filter = request.args.get('status', '').lower()
    search = request.args.get('q', '').lower()

    result = vulnerabilities_store[:]
    if severity_filter and severity_filter != 'all':
        result = [v for v in result if v.get('Severity', '').lower() == severity_filter]
    if status_filter and status_filter not in ('all', ''):
        result = [v for v in result if v.get('Status', '').lower() == status_filter]
    if search:
        result = [v for v in result if
                  search in v.get('Test', '').lower() or
                  search in v.get('Finding', '').lower() or
                  search in v.get('target_url', '').lower()]

    indexed = []
    for i, v in enumerate(result):
        entry = dict(v)
        entry['id'] = vulnerabilities_store.index(v) + 1  # stable global id
        entry['_display_status'] = 'Fixed' if v.get('_fixed') else v.get('Status', 'Open')
        indexed.append(entry)

    return jsonify({'vulnerabilities': indexed, 'total': len(indexed)})


@app.route('/api/reports')
@login_required
def api_reports():
    return jsonify({'reports': list(reversed(reports_store))})


@app.route('/api/scan-logs')
@login_required
def api_scan_logs():
    """Return all accumulated logs for the current or last scan."""
    return jsonify({
        'running': active_scan['running'],
        'target': active_scan['target'],
        'logs': active_scan['logs'],
    })


@app.route('/api/reset-scan', methods=['POST'])
@login_required
def api_reset_scan():
    """Clear scan results and logs so the scanning page starts fresh."""
    if not active_scan['running']:
        scan_results.clear()
        active_scan['logs'] = []
        active_scan['target'] = ''
    return jsonify({'status': 'ok', 'running': active_scan['running']})


# ─────────────────────────────────────────────
#  VAPT SCAN API ROUTES
# ─────────────────────────────────────────────

@app.route('/test-auth', methods=['POST'])
@login_required
def test_auth():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        auth_type = data.get('auth_type', 'none')
        auth_data = data.get('auth_data', {})

        if not target:
            return jsonify({'status': 'error', 'message': 'Please enter a valid target URL'})

        print(f"\n[*] Testing authentication for: {target}")
        print(f"[*] Auth type: {auth_type}")

        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        req_session = requests.Session()

        if auth_type == 'form':
            login_url = auth_data.get('login_url', '').strip()
            username = auth_data.get('username', '').strip()
            password = auth_data.get('password', '').strip()
            username_field = auth_data.get('username_field', 'username')
            password_field = auth_data.get('password_field', 'password')
            success_indicator = auth_data.get('success_indicator', '').strip()

            if not all([login_url, username, password]):
                return jsonify({'status': 'error', 'message': 'Please fill in all required fields'})

            try:
                req_session.verify = False
                login_page = req_session.get(login_url, timeout=15, allow_redirects=True)
                hidden_fields = {}
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(login_page.text, 'html.parser')
                    for hidden in soup.find_all('input', {'type': 'hidden'}):
                        n = hidden.get('name')
                        v = hidden.get('value')
                        if n and n not in [username_field, password_field]:
                            hidden_fields[n] = v
                except Exception:
                    pass

                login_data = {username_field: username, password_field: password}
                login_data.update(hidden_fields)
                login_response = req_session.post(login_url, data=login_data, allow_redirects=True, timeout=15)

                failure_keywords = ['invalid', 'incorrect', 'wrong', 'failed', 'error',
                                    'bad credentials', 'unauthorized', 'authentication failed', 'login failed']
                has_failure = any(kw in login_response.text.lower() for kw in failure_keywords)
                url_changed = login_response.url != login_url

                test_sess = requests.Session()
                test_sess.verify = False
                wrong_data = login_data.copy()
                wrong_data[password_field] = "WRONG_PASSWORD_XYZ_123_" + password
                wrong_response = test_sess.post(login_url, data=wrong_data, allow_redirects=True, timeout=15)
                response_differs = (len(login_response.text) != len(wrong_response.text)) or (login_response.url != wrong_response.url)

                login_success = False
                success_reason = ""
                if success_indicator and success_indicator.lower() in login_response.text.lower():
                    login_success = True
                    success_reason = f'Found success indicator "{success_indicator}"'
                elif url_changed and response_differs:
                    login_success = True
                    success_reason = 'Authentication verified (URL changed & responses differ)'
                elif url_changed and not has_failure:
                    login_success = True
                    success_reason = 'Page changed after login (no errors detected)'
                elif response_differs and not has_failure:
                    login_success = True
                    success_reason = 'Responses differ (authentication working)'

                if login_success:
                    auth_sessions[target] = {
                        'type': 'form', 'session': req_session,
                        'cookies': req_session.cookies.get_dict(),
                        'login_url': login_url, 'login_data': login_data,
                    }
                    return jsonify({'status': 'success', 'message': f'Login Successful! {success_reason}'})
                else:
                    return jsonify({'status': 'error', 'message': 'Login Failed! Please check your credentials.'})

            except requests.exceptions.Timeout:
                return jsonify({'status': 'error', 'message': f'Connection Timeout: {login_url}'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Error: {str(e)}'})

        elif auth_type == 'basic':
            username = auth_data.get('username', '').strip()
            password = auth_data.get('password', '').strip()
            if not all([username, password]):
                return jsonify({'status': 'error', 'message': 'Please fill in both username and password'})
            try:
                resp_ok = requests.get(target, auth=(username, password), timeout=15, verify=False, allow_redirects=True)
                resp_bad = requests.get(target, auth=(username, "wrong_xyz123"), timeout=15, verify=False, allow_redirects=True)
                resp_none = requests.get(target, timeout=15, verify=False, allow_redirects=True)
                if (resp_none.status_code == 401 or resp_bad.status_code == 401) and resp_ok.status_code == 200:
                    auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
                    return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful!'})
                elif resp_ok.status_code == 200 and resp_ok.text != resp_bad.text:
                    auth_sessions[target] = {'type': 'basic', 'username': username, 'password': password}
                    return jsonify({'status': 'success', 'message': 'HTTP Basic Authentication successful! (content-based)'})
                else:
                    return jsonify({'status': 'error', 'message': 'Could not verify basic authentication.'})
            except requests.exceptions.Timeout:
                return jsonify({'status': 'error', 'message': 'Authentication test timed out.'})
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Basic auth test error: {str(e)}'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid authentication type'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Authentication test failed: {str(e)}'})


@app.route('/scan-progress')
@login_required
def scan_progress():
    """SSE endpoint — streams log lines and phase events in real time."""
    def generate():
        while active_scan['running']:
            try:
                update = update_queue.get(timeout=1)
                yield f"data: {json.dumps(update)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        yield f"data: {json.dumps({'type': 'complete'})}\n\n"

    return Response(generate(), mimetype='text/event-stream')


@app.route('/scan', methods=['POST'])
@login_required
def scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        auth_type = data.get('auth_type', 'none')
        auth_data_payload = data.get('auth_data', {})
        owasp_enabled = data.get('owasp_enabled', True)

        if not target:
            return jsonify({'status': 'error', 'message': 'Please enter a valid target URL or IP address'})

        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"

        print(f"\n[*] Starting scan for: {target}")

        auth_credentials = None
        if auth_type != 'none' and auth_data_payload:
            auth_credentials = {
                'type': auth_type,
                'data': auth_data_payload,
                'session': auth_sessions.get(target)
            }

        # Reset state for new scan
        active_scan['running'] = True
        active_scan['target'] = target
        active_scan['logs'] = []
        scan_results.clear()

        while not update_queue.empty():
            try:
                update_queue.get_nowait()
            except queue.Empty:
                break

        def run_scan():
            import time as _time
            _scan_start = _time.time()
            try:
                log(f"🚀 Scan started for {target}")
                log(f"🔐 Authentication: {auth_type}")

                def progress_cb(msg):
                    """Forward vapt_auto events to SSE queue AND log panel."""
                    update_queue.put(msg)
                    if isinstance(msg, dict):
                        mtype = msg.get('type', '')
                        if mtype == 'phase':
                            log(f"📋 Phase {msg.get('phase')}: {msg.get('name')}")
                        elif mtype == 'crawling':
                            log(f"🕷️ Crawling [{msg.get('count')}/{msg.get('total')}]: {msg.get('url')}")
                        elif mtype == 'crawl_complete':
                            log(f"✅ Crawl done — {msg.get('total_paths')} paths from {msg.get('pages_crawled')} pages")
                        elif mtype == 'crawl_start':
                            log(f"🕷️ Starting crawler (max {msg.get('max_pages')} pages)...")

                result = perform_vapt_scan(
                    target,
                    auth_credentials=auth_credentials,
                    owasp_enabled=owasp_enabled,
                    progress_callback=progress_cb
                )

                if result['status'] == 'success':
                    raw_results = result['results']
                    filename = result['filename']

                    # Tag each finding
                    for r in raw_results:
                        r['target_url'] = target
                        r['scan_date'] = datetime.now().strftime('%Y-%m-%d %H:%M')

                    # Add to global vulnerability list
                    vulnerabilities_store.extend(raw_results)

                    # Recompute dashboard
                    rebuild_dashboard_stats()

                    # Update/create target record
                    tid = get_or_create_target(target)
                    sc = severity_counts(raw_results)
                    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M')
                    targets_store[tid]['last_scan'] = scan_time
                    targets_store[tid]['status'] = 'Active'
                    targets_store[tid]['scan_count'] = targets_store[tid].get('scan_count', 0) + 1
                    targets_store[tid]['total_vulns'] = len(raw_results)
                    targets_store[tid]['vuln_counts'] = {
                        'critical': sc['critical'],
                        'high': sc['high'],
                        'medium': sc['medium'],
                        'low': sc['low'],
                    }
                    # Append to scan history (most recent first, keep last 20)
                    history_entry = {
                        'scan_time': scan_time,
                        'total': len(raw_results),
                        'critical': sc['critical'],
                        'high': sc['high'],
                        'medium': sc['medium'],
                        'low': sc['low'],
                        'report': filename,
                    }
                    if 'scan_history' not in targets_store[tid]:
                        targets_store[tid]['scan_history'] = []
                    targets_store[tid]['scan_history'].insert(0, history_entry)
                    targets_store[tid]['scan_history'] = targets_store[tid]['scan_history'][:20]

                    # Add report record
                    reports_counter[0] += 1
                    rid = reports_counter[0]
                    target_name = target.replace('https://', '').replace('http://', '').split('/')[0]
                    reports_store.append({
                        'id': rid,
                        'name': f"Full Security Scan – {target_name}",
                        'target_url': target,
                        'filename': filename,
                        'date': datetime.now().strftime('%Y-%m-%d'),
                        'status': 'Completed',
                        'vuln_counts': {
                            'critical': sc['critical'],
                            'high': sc['high'],
                            'medium': sc['medium'],
                            'low': sc['low'],
                        },
                        'total': len(raw_results),
                    })

                    scan_results['last_file'] = filename
                    scan_results['last_result'] = result

                    _runtime = int(_time.time() - _scan_start)
                    reports_store[-1]['runtime_seconds'] = _runtime
                    reports_store[-1]['scan_time'] = scan_time

                    log(f"✅ Scan complete! {len(raw_results)} findings — Report: {filename}")
                    log(f"📊 Critical:{sc['critical']} High:{sc['high']} Medium:{sc['medium']} Low:{sc['low']}")
                    log(f"⏱️ Runtime: {_runtime}s")
                else:
                    scan_results['last_error'] = result.get('message', 'Unknown error')
                    log(f"❌ Scan failed: {result.get('message')}")

            except Exception as e:
                print(f"[!] Scan error: {str(e)}")
                scan_results['last_error'] = str(e)
                log(f"❌ Error: {str(e)}")
            finally:
                active_scan['running'] = False

        t = threading.Thread(target=run_scan)
        t.daemon = True
        t.start()

        return jsonify({'status': 'started', 'message': 'Scan started.'})

    except Exception as e:
        active_scan['running'] = False
        return jsonify({'status': 'error', 'message': f'Scan failed: {str(e)}'})


@app.route('/scan-status')
@login_required
def scan_status():
    if active_scan['running']:
        return jsonify({'status': 'running'})
    elif 'last_result' in scan_results:
        result = scan_results['last_result']
        return jsonify({
            'status': 'success',
            'filename': result['filename'],
            'results': result['results'],
        })
    elif 'last_error' in scan_results:
        return jsonify({'status': 'error', 'message': scan_results['last_error']})
    else:
        return jsonify({'status': 'idle'})


@app.route('/download')
@login_required
def download():
    try:
        filename = scan_results.get('last_file')
        if not filename:
            return jsonify({'status': 'error', 'message': 'No report available for download'})
        if not os.path.exists(filename):
            return jsonify({'status': 'error', 'message': 'Report file not found'})
        return send_file(filename, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Download failed: {str(e)}'})


@app.route('/api/vulnerabilities/<int:vuln_id>')
@login_required
def api_vulnerability_detail(vuln_id):
    """Return a single vulnerability by 1-based id."""
    idx = vuln_id - 1
    if idx < 0 or idx >= len(vulnerabilities_store):
        return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
    entry = dict(vulnerabilities_store[idx])
    entry['id'] = vuln_id
    # Use display status if it has been toggled
    if entry.get('_fixed'):
        entry['_display_status'] = 'Fixed'
    else:
        entry['_display_status'] = entry.get('Status', 'Open')
    return jsonify({'status': 'success', 'vulnerability': entry})


@app.route('/api/vulnerabilities/<int:vuln_id>/fix', methods=['POST'])
@login_required
def api_vulnerability_fix(vuln_id):
    """Toggle fixed/unfixed on a vulnerability."""
    idx = vuln_id - 1
    if idx < 0 or idx >= len(vulnerabilities_store):
        return jsonify({'status': 'error', 'message': 'Vulnerability not found'}), 404
    v = vulnerabilities_store[idx]
    if v.get('_fixed'):
        v['_fixed'] = False
        new_status = v.get('Status', 'Open')
    else:
        v['_fixed'] = True
        new_status = 'Fixed'
    return jsonify({'status': 'success', 'new_status': new_status, 'fixed': v['_fixed']})


@app.route('/download-report/<int:report_id>')
@login_required
def download_report(report_id):
    """Download a specific historical report by ID."""
    report = next((r for r in reports_store if r['id'] == report_id), None)
    if not report:
        return jsonify({'status': 'error', 'message': 'Report not found'})
    filename = report['filename']
    if not os.path.exists(filename):
        return jsonify({'status': 'error', 'message': 'Report file not found on disk'})
    return send_file(filename, as_attachment=True, download_name=os.path.basename(filename))


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 80)
    print("              ADVANCED VAPT SCANNER PRO")
    print("          Vulnerability Assessment & Penetration Testing Tool")
    print("=" * 80)
    print("\n[+] Server starting...")
    print("[+] Access the scanner at: http://localhost:5005")
    print("[+] Login credentials:")
    print("    admin@vapt.pro  /  Admin@1234")
    print("[+] Press Ctrl+C to stop\n")
    print("=" * 80)
    print("\n⚠️  LEGAL NOTICE: Only scan systems you own or have permission to test!")
    print("=" * 80 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5005)