/**
 * OpenEASD Frontend Application
 * Handles API interactions for domain management, scans, and findings
 */

const API_BASE = '/api/v1';

// Polling intervals for active scans
let scanPollingIntervals = {};

// ============================================
// Initialization
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    loadDomains();
    loadScans();
    loadFindings();
    loadFindingsStats();
    loadJobs();
    loadJobStats();
});

function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active from all tabs and contents
            tabs.forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            // Add active to clicked tab and corresponding content
            tab.classList.add('active');
            document.getElementById(`${tab.dataset.tab}-tab`).classList.add('active');

            // Refresh data based on tab
            if (tab.dataset.tab === 'domains') loadDomains();
            if (tab.dataset.tab === 'scans') loadScans();
            if (tab.dataset.tab === 'findings') {
                loadFindings();
                loadFindingsStats();
            }
            if (tab.dataset.tab === 'jobs') {
                loadJobs();
                loadJobStats();
            }
        });
    });
}

// ============================================
// API Helpers
// ============================================

async function apiCall(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };

    const response = await fetch(url, { ...defaultOptions, ...options });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(error.detail || `HTTP ${response.status}`);
    }

    // Handle 204 No Content
    if (response.status === 204) {
        return null;
    }

    return response.json();
}

// ============================================
// Domain Management
// ============================================

async function loadDomains() {
    const tbody = document.getElementById('domains-body');
    tbody.innerHTML = '<tr><td colspan="5" class="loading">Loading domains...</td></tr>';

    try {
        const data = await apiCall('/domains?limit=100');

        if (!data.domains || data.domains.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="empty-state">
                        <h3>No domains yet</h3>
                        <p>Add your first domain to start scanning</p>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = data.domains.map(domain => `
            <tr>
                <td>
                    ${domain.domain}
                    ${domain.is_primary ? '<span class="primary-badge">PRIMARY</span>' : ''}
                </td>
                <td>${domain.is_primary ? 'Yes' : 'No'}</td>
                <td>${domain.scan_count || 0}</td>
                <td>${domain.last_scanned_at ? formatDate(domain.last_scanned_at) : 'Never'}</td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-primary" onclick="scanDomain('${domain.domain}')">Scan</button>
                        <button class="btn btn-sm btn-secondary" onclick="editDomain('${domain.domain}')">Edit</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteDomain('${domain.domain}')">Delete</button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="5" class="loading">Error: ${error.message}</td></tr>`;
        showToast('Failed to load domains: ' + error.message, 'error');
    }
}

function showAddDomainModal() {
    document.getElementById('add-domain-form').reset();
    document.getElementById('add-domain-modal-title').textContent = 'Add New Domain';
    document.getElementById('domain-name').disabled = false;
    document.getElementById('add-domain-form').dataset.mode = 'add';
    delete document.getElementById('add-domain-form').dataset.editDomain;
    openModal('add-domain-modal');
}

async function editDomain(domainName) {
    try {
        const domain = await apiCall(`/domains/${domainName}`);

        document.getElementById('add-domain-modal-title').textContent = 'Edit Domain';
        document.getElementById('domain-name').value = domainName;
        document.getElementById('domain-name').disabled = true;
        document.getElementById('is-primary').checked = domain.is_primary;
        document.getElementById('contact-email').value = domain.contact_email || '';
        document.getElementById('scan-frequency').value = domain.scan_frequency || 'weekly';

        document.getElementById('add-domain-form').dataset.mode = 'edit';
        document.getElementById('add-domain-form').dataset.editDomain = domainName;

        openModal('add-domain-modal');
    } catch (error) {
        showToast('Failed to load domain details: ' + error.message, 'error');
    }
}

async function addDomain(event) {
    event.preventDefault();

    const form = document.getElementById('add-domain-form');
    const mode = form.dataset.mode || 'add';
    const domain = document.getElementById('domain-name').value.trim();
    const isPrimary = document.getElementById('is-primary').checked;
    const contactEmail = document.getElementById('contact-email').value.trim();
    const scanFrequency = document.getElementById('scan-frequency').value;

    try {
        if (mode === 'edit') {
            const editDomain = form.dataset.editDomain;
            await apiCall(`/domains/${editDomain}`, {
                method: 'PUT',
                body: JSON.stringify({
                    is_primary: isPrimary,
                    contact_email: contactEmail || null,
                    scan_frequency: scanFrequency
                })
            });
            showToast(`Domain "${editDomain}" updated successfully`, 'success');
        } else {
            await apiCall('/domains', {
                method: 'POST',
                body: JSON.stringify({
                    domain: domain,
                    is_primary: isPrimary,
                    contact_email: contactEmail || null,
                    scan_frequency: scanFrequency
                })
            });
            showToast(`Domain "${domain}" added successfully`, 'success');
        }

        closeModal('add-domain-modal');
        loadDomains();
        updateScanDomainDropdown();
    } catch (error) {
        showToast('Failed to save domain: ' + error.message, 'error');
    }
}

async function deleteDomain(domain) {
    if (!confirm(`Are you sure you want to delete "${domain}"?\n\nThis will remove all associated scan data.`)) {
        return;
    }

    try {
        await apiCall(`/domains/${domain}`, { method: 'DELETE' });
        showToast(`Domain "${domain}" deleted successfully`, 'success');
        loadDomains();
        updateScanDomainDropdown();
    } catch (error) {
        showToast('Failed to delete domain: ' + error.message, 'error');
    }
}

async function scanDomain(domain) {
    try {
        const data = await apiCall('/scans', {
            method: 'POST',
            body: JSON.stringify({
                domain: domain,
                timeout: 300
            })
        });

        showToast(`Scan started for "${domain}"`, 'success');

        // Switch to scans tab
        document.querySelector('[data-tab="scans"]').click();

        // Start polling for this scan
        startScanPolling(data.scan_id);
    } catch (error) {
        showToast('Failed to start scan: ' + error.message, 'error');
    }
}

// ============================================
// Scan Management
// ============================================

async function loadScans() {
    const tbody = document.getElementById('scans-body');
    tbody.innerHTML = '<tr><td colspan="6" class="loading">Loading scans...</td></tr>';

    try {
        const data = await apiCall('/scans?limit=50');

        if (!data.scans || data.scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <h3>No scans yet</h3>
                        <p>Start a scan from the Domains tab</p>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = data.scans.map(scan => `
            <tr>
                <td><code>${scan.scan_id.substring(0, 8)}...</code></td>
                <td>${scan.domain || 'N/A'}</td>
                <td><span class="badge badge-${scan.status} ${scan.status === 'running' ? 'status-running' : ''}">${scan.status}</span></td>
                <td>${scan.start_time ? formatDate(scan.start_time) : 'Pending'}</td>
                <td>${scan.findings_count || 0}</td>
                <td>
                    <div class="action-buttons">
                        ${scan.status === 'completed' ?
                            `<button class="btn btn-sm btn-secondary" onclick="viewScanResults('${scan.scan_id}')">View Results</button>` :
                            scan.status === 'running' || scan.status === 'pending' ?
                            `<button class="btn btn-sm btn-danger" onclick="cancelScan('${scan.scan_id}')">Cancel</button>` :
                            scan.status === 'failed' ?
                            `<button class="btn btn-sm btn-primary" onclick="retryScan('${scan.scan_id}')">Retry</button>` :
                            `<button class="btn btn-sm btn-secondary" disabled>${scan.status}</button>`
                        }
                        ${scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled' ?
                            `<button class="btn btn-sm btn-danger" onclick="deleteScan('${scan.scan_id}')">Delete</button>` : ''
                        }
                    </div>
                </td>
            </tr>
        `).join('');

        // Start polling for running scans
        data.scans.filter(s => s.status === 'running' || s.status === 'pending').forEach(scan => {
            startScanPolling(scan.scan_id);
        });
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="6" class="loading">Error: ${error.message}</td></tr>`;
        showToast('Failed to load scans: ' + error.message, 'error');
    }
}

function showNewScanModal() {
    updateScanDomainDropdown();
    openModal('new-scan-modal');
}

async function updateScanDomainDropdown() {
    const select = document.getElementById('scan-domain');

    try {
        const data = await apiCall('/domains?limit=100');
        select.innerHTML = '<option value="">-- Select a domain --</option>';

        if (data.domains) {
            data.domains.forEach(domain => {
                select.innerHTML += `<option value="${domain.domain}">${domain.domain}${domain.is_primary ? ' (Primary)' : ''}</option>`;
            });
        }
    } catch (error) {
        console.error('Failed to load domains for dropdown:', error);
    }
}

async function startScan(event) {
    event.preventDefault();

    const domain = document.getElementById('scan-domain').value;
    const timeout = parseInt(document.getElementById('scan-timeout').value);

    if (!domain) {
        showToast('Please select a domain', 'warning');
        return;
    }

    try {
        const data = await apiCall('/scans', {
            method: 'POST',
            body: JSON.stringify({
                domain: domain,
                timeout: timeout
            })
        });

        closeModal('new-scan-modal');
        showToast(`Scan started for "${domain}"`, 'success');
        loadScans();

        // Start polling for this scan
        startScanPolling(data.scan_id);
    } catch (error) {
        showToast('Failed to start scan: ' + error.message, 'error');
    }
}

async function startBatchScan(primaryOnly = false) {
    try {
        const data = await apiCall('/scans/batch', {
            method: 'POST',
            body: JSON.stringify({
                primary_only: primaryOnly,
                timeout: 300
            })
        });

        closeModal('new-scan-modal');

        if (data.total_queued === 0) {
            showToast('No domains found to scan', 'warning');
            return;
        }

        showToast(data.message, 'success');
        loadScans();

        // Start polling for all queued scans
        data.scans.forEach(scan => {
            startScanPolling(scan.scan_id);
        });
    } catch (error) {
        showToast('Failed to start batch scan: ' + error.message, 'error');
    }
}

async function cancelScan(scanId) {
    if (!confirm('Are you sure you want to cancel this scan?')) {
        return;
    }

    try {
        await apiCall(`/scans/${scanId}/cancel`, { method: 'POST' });

        // Stop polling for this scan
        if (scanPollingIntervals[scanId]) {
            clearInterval(scanPollingIntervals[scanId]);
            delete scanPollingIntervals[scanId];
        }

        showToast('Scan cancelled', 'success');
        loadScans();
    } catch (error) {
        showToast('Failed to cancel scan: ' + error.message, 'error');
    }
}

async function retryScan(scanId) {
    try {
        const data = await apiCall(`/scans/${scanId}/retry`, {
            method: 'POST',
            body: JSON.stringify({})
        });

        showToast('Scan retry started', 'success');
        loadScans();

        // Start polling for the new scan
        startScanPolling(data.scan_id);
    } catch (error) {
        showToast('Failed to retry scan: ' + error.message, 'error');
    }
}

async function deleteScan(scanId) {
    if (!confirm('Are you sure you want to delete this scan?\n\nThis will remove all associated findings.')) {
        return;
    }

    try {
        await apiCall(`/scans/${scanId}`, { method: 'DELETE' });
        showToast('Scan deleted', 'success');
        loadScans();
        loadFindings();
        loadFindingsStats();
    } catch (error) {
        showToast('Failed to delete scan: ' + error.message, 'error');
    }
}

function startScanPolling(scanId) {
    // Don't start if already polling
    if (scanPollingIntervals[scanId]) return;

    scanPollingIntervals[scanId] = setInterval(async () => {
        try {
            const scan = await apiCall(`/scans/${scanId}`);

            if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') {
                clearInterval(scanPollingIntervals[scanId]);
                delete scanPollingIntervals[scanId];
                loadScans();
                loadFindings();
                loadFindingsStats();

                if (scan.status === 'completed') {
                    showToast(`Scan completed for "${scan.domain}"`, 'success');
                } else if (scan.status === 'failed') {
                    showToast(`Scan failed for "${scan.domain}"`, 'error');
                } else {
                    showToast(`Scan cancelled for "${scan.domain}"`, 'warning');
                }
            }
        } catch (error) {
            console.error('Polling error:', error);
        }
    }, 3000); // Poll every 3 seconds
}

async function viewScanResults(scanId) {
    const content = document.getElementById('scan-results-content');
    content.innerHTML = '<div class="loading">Loading results...</div>';
    openModal('scan-results-modal');

    try {
        const data = await apiCall(`/scans/${scanId}/results`);

        content.innerHTML = `
            <div class="finding-detail">
                <div class="results-section">
                    <h4>Scan Information</h4>
                    <div class="detail-row">
                        <span class="detail-label">Domain:</span>
                        <span class="detail-value">${data.scan.domain || 'N/A'}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Status:</span>
                        <span class="detail-value"><span class="badge badge-${data.scan.status}">${data.scan.status}</span></span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Started:</span>
                        <span class="detail-value">${data.scan.start_time ? formatDate(data.scan.start_time) : 'N/A'}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Completed:</span>
                        <span class="detail-value">${data.scan.end_time ? formatDate(data.scan.end_time) : 'N/A'}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Findings:</span>
                        <span class="detail-value">${data.scan.findings_count || 0}</span>
                    </div>
                </div>

                <div class="results-section">
                    <h4>Subdomains Found (${data.subdomains ? data.subdomains.length : 0})</h4>
                    <div class="results-list">
                        ${data.subdomains && data.subdomains.length > 0 ?
                            data.subdomains.map(s => `<div class="item">${s.subdomain} <span class="text-muted">(${s.ip_address || 'N/A'})</span></div>`).join('') :
                            '<div class="item">No subdomains found</div>'
                        }
                    </div>
                </div>

                <div class="results-section">
                    <h4>Open Ports Found (${data.ports ? data.ports.length : 0})</h4>
                    <div class="results-list">
                        ${data.ports && data.ports.length > 0 ?
                            data.ports.map(p => `<div class="item">${p.subdomain}:${p.port} <span class="text-muted">(${p.protocol})</span></div>`).join('') :
                            '<div class="item">No open ports found</div>'
                        }
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        content.innerHTML = `<div class="loading">Error: ${error.message}</div>`;
    }
}

// ============================================
// Findings Management
// ============================================

async function loadFindings() {
    const tbody = document.getElementById('findings-body');
    tbody.innerHTML = '<tr><td colspan="6" class="loading">Loading findings...</td></tr>';

    const severity = document.getElementById('severity-filter').value;
    const status = document.getElementById('status-filter')?.value;
    const params = new URLSearchParams({ limit: '100' });
    if (severity) params.append('min_severity', severity);

    try {
        const data = await apiCall(`/findings?${params}`);

        if (!data.findings || data.findings.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        <h3>No findings yet</h3>
                        <p>Run a scan to discover security findings</p>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = data.findings.map(finding => `
            <tr>
                <td><span class="badge badge-${finding.severity}">${finding.severity}</span></td>
                <td>${finding.finding_type || 'Unknown'}</td>
                <td><code>${finding.affected_asset || 'N/A'}</code></td>
                <td>${finding.risk_score || 'N/A'}</td>
                <td><span class="badge badge-status-${finding.status || 'new'}">${finding.status || 'new'}</span></td>
                <td>
                    <div class="action-buttons">
                        <button class="btn btn-sm btn-secondary" onclick="viewFindingDetails('${finding.id}')">Details</button>
                        <button class="btn btn-sm btn-icon" onclick="updateFindingStatus('${finding.id}')" title="Update Status">
                            <span>&#8634;</span>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="6" class="loading">Error: ${error.message}</td></tr>`;
        showToast('Failed to load findings: ' + error.message, 'error');
    }
}

async function loadFindingsStats() {
    try {
        const data = await apiCall('/findings/stats');

        // Update stat cards
        document.getElementById('stat-critical').textContent = data.critical_findings || 0;
        document.getElementById('stat-high').textContent = data.high_findings || 0;
        document.getElementById('stat-medium').textContent = data.medium_findings || 0;
        document.getElementById('stat-low').textContent = data.low_findings || 0;

        // Update info if element exists
        const infoEl = document.getElementById('stat-info');
        if (infoEl) {
            infoEl.textContent = data.info_findings || 0;
        }

        // Update total if element exists
        const totalEl = document.getElementById('stat-total');
        if (totalEl) {
            totalEl.textContent = data.total_findings || 0;
        }
    } catch (error) {
        console.error('Failed to load findings stats:', error);
    }
}

async function viewFindingDetails(findingId) {
    const content = document.getElementById('finding-details-content');
    content.innerHTML = '<div class="loading">Loading details...</div>';
    openModal('finding-details-modal');

    try {
        const finding = await apiCall(`/findings/${findingId}`);

        content.innerHTML = `
            <div class="finding-detail">
                <div class="detail-row">
                    <span class="detail-label">ID:</span>
                    <span class="detail-value"><code>${finding.id}</code></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Severity:</span>
                    <span class="detail-value"><span class="badge badge-${finding.severity}">${finding.severity}</span></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value">${finding.finding_type || 'Unknown'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Title:</span>
                    <span class="detail-value">${finding.title || finding.finding_type || 'Unknown'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Asset:</span>
                    <span class="detail-value"><code>${finding.affected_asset || 'N/A'}</code></span>
                </div>
                ${finding.port ? `
                <div class="detail-row">
                    <span class="detail-label">Port:</span>
                    <span class="detail-value">${finding.port}/${finding.protocol || 'tcp'}</span>
                </div>
                ` : ''}
                ${finding.service_name ? `
                <div class="detail-row">
                    <span class="detail-label">Service:</span>
                    <span class="detail-value">${finding.service_name}</span>
                </div>
                ` : ''}
                <div class="detail-row">
                    <span class="detail-label">Risk Score:</span>
                    <span class="detail-value"><strong>${finding.risk_score || 'N/A'}</strong>/100</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${finding.confidence_level || 'medium'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Status:</span>
                    <span class="detail-value"><span class="badge badge-status-${finding.status || 'new'}">${finding.status || 'new'}</span></span>
                </div>
                ${finding.cwe_id ? `
                <div class="detail-row">
                    <span class="detail-label">CWE:</span>
                    <span class="detail-value"><a href="https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html" target="_blank">${finding.cwe_id}</a></span>
                </div>
                ` : ''}
                <div class="detail-row">
                    <span class="detail-label">Description:</span>
                    <span class="detail-value">${finding.description || 'No description available'}</span>
                </div>
                ${finding.evidence ? `
                <div class="detail-row" style="flex-direction: column;">
                    <span class="detail-label" style="margin-bottom: 10px;">Evidence:</span>
                    <div class="evidence-block">${JSON.stringify(finding.evidence, null, 2)}</div>
                </div>
                ` : ''}
                ${finding.score_breakdown ? `
                <div class="detail-row" style="flex-direction: column;">
                    <span class="detail-label" style="margin-bottom: 10px;">Score Breakdown:</span>
                    <div class="evidence-block">${JSON.stringify(finding.score_breakdown, null, 2)}</div>
                </div>
                ` : ''}
                ${finding.remediation ? `
                <div class="detail-row">
                    <span class="detail-label">Remediation:</span>
                    <span class="detail-value">${finding.remediation}</span>
                </div>
                ` : ''}
                <div class="detail-row">
                    <span class="detail-label">First Seen:</span>
                    <span class="detail-value">${finding.first_seen ? formatDate(finding.first_seen) : 'Unknown'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Last Seen:</span>
                    <span class="detail-value">${finding.last_seen ? formatDate(finding.last_seen) : 'Unknown'}</span>
                </div>
                ${finding.occurrence_count > 1 ? `
                <div class="detail-row">
                    <span class="detail-label">Occurrences:</span>
                    <span class="detail-value">${finding.occurrence_count}</span>
                </div>
                ` : ''}
                ${finding.resolution_notes ? `
                <div class="detail-row">
                    <span class="detail-label">Resolution Notes:</span>
                    <span class="detail-value">${finding.resolution_notes}</span>
                </div>
                ` : ''}

                <div class="form-actions" style="margin-top: 20px; border-top: 1px solid var(--border-color); padding-top: 20px;">
                    <button class="btn btn-secondary" onclick="closeModal('finding-details-modal')">Close</button>
                    <button class="btn btn-primary" onclick="updateFindingStatus('${finding.id}')">Update Status</button>
                </div>
            </div>
        `;
    } catch (error) {
        content.innerHTML = `<div class="loading">Error: ${error.message}</div>`;
    }
}

async function updateFindingStatus(findingId) {
    const statuses = [
        { value: 'new', label: 'New' },
        { value: 'open', label: 'Open' },
        { value: 'acknowledged', label: 'Acknowledged' },
        { value: 'resolved', label: 'Resolved' },
        { value: 'false_positive', label: 'False Positive' }
    ];

    const statusSelect = statuses.map(s => `<option value="${s.value}">${s.label}</option>`).join('');

    const content = document.getElementById('status-update-content');
    content.innerHTML = `
        <form id="status-update-form" onsubmit="submitStatusUpdate(event, '${findingId}')">
            <div class="form-group">
                <label for="new-status">New Status</label>
                <select id="new-status" required>
                    ${statusSelect}
                </select>
            </div>
            <div class="form-group">
                <label for="resolution-notes">Notes (optional)</label>
                <textarea id="resolution-notes" rows="3" style="width: 100%; padding: 12px; background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-color);"></textarea>
            </div>
            <div class="form-actions">
                <button type="button" class="btn btn-secondary" onclick="closeModal('status-update-modal')">Cancel</button>
                <button type="submit" class="btn btn-primary">Update</button>
            </div>
        </form>
    `;

    openModal('status-update-modal');
}

async function submitStatusUpdate(event, findingId) {
    event.preventDefault();

    const status = document.getElementById('new-status').value;
    const notes = document.getElementById('resolution-notes').value;

    try {
        await apiCall(`/findings/${findingId}`, {
            method: 'PUT',
            body: JSON.stringify({
                status: status,
                resolution_notes: notes || null
            })
        });

        closeModal('status-update-modal');
        closeModal('finding-details-modal');
        showToast('Finding status updated', 'success');
        loadFindings();
        loadFindingsStats();
    } catch (error) {
        showToast('Failed to update status: ' + error.message, 'error');
    }
}

// ============================================
// Job Management
// ============================================

async function loadJobs() {
    const tbody = document.getElementById('jobs-body');
    tbody.innerHTML = '<tr><td colspan="7" class="loading">Loading jobs...</td></tr>';

    const status = document.getElementById('job-status-filter')?.value;
    const params = new URLSearchParams({ limit: '100' });
    if (status) params.append('status', status);

    try {
        const data = await apiCall(`/jobs?${params}`);

        if (!data.jobs || data.jobs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">
                        <h3>No jobs yet</h3>
                        <p>Jobs are created when scans are started</p>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = data.jobs.map(job => `
            <tr>
                <td><code>${job.id.substring(0, 8)}...</code></td>
                <td>${job.job_type || 'scan'}</td>
                <td>${job.domain || 'N/A'}</td>
                <td><span class="badge badge-job-${job.status} ${job.status === 'processing' ? 'status-running' : ''}">${job.status}</span></td>
                <td>${job.worker_id ? `<code>${job.worker_id.substring(0, 8)}...</code>` : '-'}</td>
                <td>${job.updated_at ? formatRelativeTime(job.updated_at) : 'N/A'}</td>
                <td>
                    <div class="action-buttons">
                        ${job.status === 'failed' ?
                            `<button class="btn btn-sm btn-primary" onclick="retryJob('${job.id}')">Retry</button>` : ''}
                        ${job.status === 'pending' || job.status === 'queued' ?
                            `<button class="btn btn-sm btn-danger" onclick="cancelJob('${job.id}')">Cancel</button>` : ''}
                        ${job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled' ?
                            `<button class="btn btn-sm btn-secondary" disabled>${job.status}</button>` : ''}
                        ${job.status === 'processing' ?
                            `<button class="btn btn-sm btn-warning" disabled>In Progress</button>` : ''}
                    </div>
                </td>
            </tr>
        `).join('');

        // Start polling for processing jobs
        data.jobs.filter(j => j.status === 'processing' || j.status === 'pending' || j.status === 'queued').forEach(job => {
            startJobPolling(job.id);
        });
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="7" class="loading">Error: ${error.message}</td></tr>`;
        showToast('Failed to load jobs: ' + error.message, 'error');
    }
}

async function loadJobStats() {
    try {
        const data = await apiCall('/jobs/statistics');

        // Update stat cards
        document.getElementById('stat-job-pending').textContent = data.pending || 0;
        document.getElementById('stat-job-queued').textContent = data.queued || 0;
        document.getElementById('stat-job-processing').textContent = data.processing || 0;
        document.getElementById('stat-job-completed').textContent = data.completed || 0;
        document.getElementById('stat-job-failed').textContent = data.failed || 0;
        document.getElementById('stat-job-cancelled').textContent = data.cancelled || 0;
    } catch (error) {
        console.error('Failed to load job stats:', error);
    }
}

// Polling intervals for active jobs
let jobPollingIntervals = {};

function startJobPolling(jobId) {
    // Don't start if already polling
    if (jobPollingIntervals[jobId]) return;

    jobPollingIntervals[jobId] = setInterval(async () => {
        try {
            const job = await apiCall(`/jobs/${jobId}`);

            if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
                clearInterval(jobPollingIntervals[jobId]);
                delete jobPollingIntervals[jobId];
                loadJobs();
                loadJobStats();

                if (job.status === 'completed') {
                    showToast(`Job completed for "${job.domain || 'unknown'}"`, 'success');
                } else if (job.status === 'failed') {
                    showToast(`Job failed for "${job.domain || 'unknown'}"`, 'error');
                } else {
                    showToast(`Job cancelled for "${job.domain || 'unknown'}"`, 'warning');
                }
            }
        } catch (error) {
            console.error('Job polling error:', error);
        }
    }, 3000); // Poll every 3 seconds
}

async function retryJob(jobId) {
    if (!confirm('Are you sure you want to retry this failed job?')) {
        return;
    }

    try {
        await apiCall(`/jobs/${jobId}/retry`, { method: 'POST' });
        showToast('Job retry initiated', 'success');
        loadJobs();
        loadJobStats();
    } catch (error) {
        showToast('Failed to retry job: ' + error.message, 'error');
    }
}

async function cancelJob(jobId) {
    if (!confirm('Are you sure you want to cancel this job?')) {
        return;
    }

    try {
        await apiCall(`/jobs/${jobId}/cancel`, { method: 'POST' });

        // Stop polling for this job
        if (jobPollingIntervals[jobId]) {
            clearInterval(jobPollingIntervals[jobId]);
            delete jobPollingIntervals[jobId];
        }

        showToast('Job cancelled', 'success');
        loadJobs();
        loadJobStats();
    } catch (error) {
        showToast('Failed to cancel job: ' + error.message, 'error');
    }
}

// ============================================
// Modal Helpers
// ============================================

function openModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

// Close modal on outside click
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
        e.target.classList.remove('active');
    }
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.active').forEach(modal => {
            modal.classList.remove('active');
        });
    }
});

// ============================================
// Toast Notifications
// ============================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span>${message}</span>
        <button class="close-btn" onclick="this.parentElement.remove()">&times;</button>
    `;
    container.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// ============================================
// Utility Functions
// ============================================

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatRelativeTime(dateString) {
    if (!dateString) return 'N/A';

    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) {
        return 'just now';
    } else if (diffMins < 60) {
        return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
        return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    } else {
        return date.toLocaleDateString();
    }
}
