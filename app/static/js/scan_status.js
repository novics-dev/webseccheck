(function() {
  'use strict';

  const el = document.getElementById('scan-data');
  if (!el) return;

  const scanId = el.dataset.scanId;
  let logOffset = 0;
  let polling = true;
  let logCount = 0;

  function updateStatus() {
    fetch('/api/scan/status/' + scanId)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        // Update status badge
        var badge = document.getElementById('status-badge');
        if (badge) {
          badge.textContent = data.status;
          badge.className = 'badge fs-6 status-' + data.status;
        }

        // Update progress bar
        var bar = document.getElementById('progress-bar');
        var label = document.getElementById('progress-label');
        if (bar && data.total_checks > 0) {
          var done = (data.passed_checks || 0) + (data.failed_checks || 0) + (data.warning_checks || 0);
          var pct = Math.round((done / data.total_checks) * 100);
          bar.style.width = pct + '%';
          bar.textContent = pct + '%';
          bar.setAttribute('aria-valuenow', pct);
          if (label) label.textContent = done + ' / ' + data.total_checks + ' checks complete';

          // Remove animation when complete
          if (pct >= 100) {
            bar.classList.remove('progress-bar-animated');
          }
        } else if (bar && data.status === 'running') {
          bar.style.width = '5%';
          bar.textContent = '';
          if (label) label.textContent = 'Starting scan...';
        }

        // Update stats
        ['total_checks', 'passed_checks', 'failed_checks', 'warning_checks'].forEach(function(k) {
          var statEl = document.getElementById(k);
          if (statEl) statEl.textContent = data[k] !== undefined ? data[k] : '0';
        });

        // Show report button when done
        if (data.status === 'completed' || data.status === 'failed') {
          var btn = document.getElementById('report-btn');
          if (btn) btn.classList.remove('d-none');

          // Stop animation
          if (bar) bar.classList.remove('progress-bar-animated', 'progress-bar-striped');
          if (data.status === 'completed' && bar) {
            bar.style.width = '100%';
            bar.textContent = '100%';
            bar.classList.add('bg-success');
            bar.classList.remove('bg-primary');
          }
          if (data.status === 'failed' && bar) {
            bar.classList.add('bg-danger');
            bar.classList.remove('bg-primary');
          }
          if (label) label.textContent = data.status === 'completed' ? 'Scan complete' : 'Scan failed';

          polling = false;
        }
      })
      .catch(function() { /* ignore network errors, keep polling */ });
  }

  function updateLogs() {
    fetch('/api/scan/logs/' + scanId + '?offset=' + logOffset)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var feed = document.getElementById('log-feed');
        var countEl = document.getElementById('log-count');
        if (!feed || !data.logs) return;

        data.logs.forEach(function(log) {
          var line = document.createElement('div');
          var level = (log.level || 'info').toLowerCase();
          line.className = 'log-' + level;

          var ts = log.timestamp || '';
          var step = log.step ? '[' + log.step + '] ' : '';
          line.textContent = '[' + ts + '] [' + level.toUpperCase() + '] ' + step + log.message;
          feed.appendChild(line);
          logCount++;
        });

        if (data.logs.length > 0) {
          logOffset += data.logs.length;
          // Keep last 200 log lines to prevent DOM bloat
          var children = feed.children;
          while (children.length > 200) {
            feed.removeChild(children[0]);
          }
          feed.scrollTop = feed.scrollHeight;
        }

        if (countEl) countEl.textContent = logCount + ' entries';
      })
      .catch(function() {});
  }

  function poll() {
    if (!polling) return;
    updateStatus();
    updateLogs();
    setTimeout(poll, 2000);
  }

  // Initial load then start polling
  updateStatus();
  updateLogs();
  setTimeout(poll, 2000);
})();
