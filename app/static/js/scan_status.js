'use strict';

function initScanStatus(scanId, statusUrl, logsUrl, reportUrl) {
  var logOffset = 0;
  var polling = true;

  function updateStatus() {
    fetch(statusUrl)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var badge = document.getElementById('status-badge');
        if (badge) {
          badge.textContent = data.status ? data.status.toUpperCase() : '';
          badge.className = 'badge fs-6 status-' + (data.status || '');
        }

        var bar = document.getElementById('progress-bar');
        var label = document.getElementById('progress-label');
        var pctEl = document.getElementById('progress-pct');

        if (bar && data.total_checks > 0) {
          var done = (data.passed_checks || 0) + (data.failed_checks || 0) + (data.warning_checks || 0);
          var pct = Math.round((done / data.total_checks) * 100);
          bar.style.width = pct + '%';
          bar.setAttribute('aria-valuenow', pct);
          if (pctEl) pctEl.textContent = pct + '%';
          if (label) label.textContent = done + ' / ' + data.total_checks + ' checks complete';
          if (pct >= 100) bar.classList.remove('progress-bar-animated');
        } else if (bar && data.status === 'running') {
          bar.style.width = '5%';
          if (label) label.textContent = 'Starting scan...';
        }

        var statMap = {
          'stat-total': 'total_checks',
          'stat-passed': 'passed_checks',
          'stat-failed': 'failed_checks',
          'stat-warnings': 'warning_checks'
        };
        Object.keys(statMap).forEach(function(id) {
          var el = document.getElementById(id);
          if (el) el.textContent = data[statMap[id]] || 0;
        });

        if (data.status === 'completed' || data.status === 'failed') {
          var btn = document.getElementById('report-btn');
          if (btn) {
            btn.href = reportUrl;
            btn.classList.remove('d-none');
          }
          if (bar) {
            bar.classList.remove('progress-bar-animated', 'progress-bar-striped');
            if (data.status === 'completed') {
              bar.style.width = '100%';
              bar.classList.replace('bg-primary', 'bg-success');
              if (label) label.textContent = 'Scan complete';
              if (pctEl) pctEl.textContent = '100%';
            } else {
              bar.classList.replace('bg-primary', 'bg-danger');
              if (label) label.textContent = 'Scan failed';
            }
          }
          polling = false;
        }
      })
      .catch(function() {});
  }

  function updateLogs() {
    fetch(logsUrl + '?offset=' + logOffset)
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var feed = document.getElementById('log-container');
        if (!feed || !data.logs || !data.logs.length) return;

        // Clear placeholder on first entry
        if (logOffset === 0 && data.logs.length > 0) feed.innerHTML = '';

        data.logs.forEach(function(log) {
          var line = document.createElement('div');
          var level = (log.level || 'info').toLowerCase();
          line.className = 'log-entry log-' + level;
          var step = log.step ? '[' + log.step + '] ' : '';
          line.textContent = '[' + (log.timestamp || '') + '] [' + level.toUpperCase() + '] ' + step + log.message;
          feed.appendChild(line);
        });

        logOffset += data.logs.length;

        // Cap DOM to 200 lines
        while (feed.children.length > 200) feed.removeChild(feed.children[0]);

        var autoScroll = document.getElementById('auto-scroll');
        if (!autoScroll || autoScroll.checked) feed.scrollTop = feed.scrollHeight;
      })
      .catch(function() {});
  }

  function poll() {
    if (!polling) return;
    updateStatus();
    updateLogs();
    setTimeout(poll, 2000);
  }

  updateStatus();
  updateLogs();
  setTimeout(poll, 2000);
}
