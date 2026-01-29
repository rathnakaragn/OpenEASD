/**
 * OpenEASD Frontend Application
 * Alpine.js-based dashboard for domain management, scans, and findings
 */

const API_BASE = '/api/v1';

// Polling intervals for active scans
let scanPollingIntervals = {};

/**
 * Main Alpine.js application component
 */
function app() {
    return {
        // Tab state
        activeTab: 'domains',

        // Data arrays
        domains: [],
        scans: [],
        findings: [],

        // Loading states
        domainsLoading: true,
        scansLoading: true,
        findingsLoading: true,
        scanResultsLoading: false,
        findingDetailsLoading: false,

        // Stats
        findingsStats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },

        // Filters
        severityFilter: '',

        // Modal states
        modals: {
            addDomain: false,
            newScan: false,
            scanResults: false,
            findingDetails: false,
            statusUpdate: false
        },

        // Form data
        domainForm: {
            mode: 'add',
            domain: '',
            is_primary: false,
            contact_email: '',
            scan_frequency: 'weekly'
        },
        scanForm: {
            domain: '',
            timeout: 300
        },
        statusUpdateForm: {
            findingId: '',
            status: 'new',
            notes: ''
        },

        // Detail views
        scanResults: null,
        findingDetails: null,

        // Toast notifications
        toasts: [],

        // ============================================
        // Initialization
        // ============================================

        init() {
            this.loadDomains();
            this.loadScans();
            this.loadFindings();
            this.loadFindingsStats();
        },

        switchTab(tab) {
            this.activeTab = tab;
            if (tab === 'domains') this.loadDomains();
            if (tab === 'scans') this.loadScans();
            if (tab === 'findings') {
                this.loadFindings();
                this.loadFindingsStats();
            }
        },

        // ============================================
        // Domain Management
        // ============================================

        async loadDomains() {
            this.domainsLoading = true;
            try {
                const data = await apiCall('/domains?limit=100');
                this.domains = data.domains || [];
            } catch (error) {
                this.showToast('Failed to load domains: ' + error.message, 'error');
                this.domains = [];
            } finally {
                this.domainsLoading = false;
            }
        },

        showAddDomainModal() {
            this.domainForm = {
                mode: 'add',
                domain: '',
                is_primary: false,
                contact_email: '',
                scan_frequency: 'weekly'
            };
            this.modals.addDomain = true;
        },

        async editDomain(domainName) {
            try {
                const domain = await apiCall(`/domains/${domainName}`);
                this.domainForm = {
                    mode: 'edit',
                    domain: domainName,
                    is_primary: domain.is_primary,
                    contact_email: domain.contact_email || '',
                    scan_frequency: domain.scan_frequency || 'weekly'
                };
                this.modals.addDomain = true;
            } catch (error) {
                this.showToast('Failed to load domain details: ' + error.message, 'error');
            }
        },

        async saveDomain() {
            try {
                if (this.domainForm.mode === 'edit') {
                    await apiCall(`/domains/${this.domainForm.domain}`, {
                        method: 'PUT',
                        body: JSON.stringify({
                            is_primary: this.domainForm.is_primary,
                            contact_email: this.domainForm.contact_email || null,
                            scan_frequency: this.domainForm.scan_frequency
                        })
                    });
                    this.showToast(`Domain "${this.domainForm.domain}" updated successfully`, 'success');
                } else {
                    await apiCall('/domains', {
                        method: 'POST',
                        body: JSON.stringify({
                            domain: this.domainForm.domain,
                            is_primary: this.domainForm.is_primary,
                            contact_email: this.domainForm.contact_email || null,
                            scan_frequency: this.domainForm.scan_frequency
                        })
                    });
                    this.showToast(`Domain "${this.domainForm.domain}" added successfully`, 'success');
                }
                this.modals.addDomain = false;
                this.loadDomains();
            } catch (error) {
                this.showToast('Failed to save domain: ' + error.message, 'error');
            }
        },

        async deleteDomain(domain) {
            if (!confirm(`Are you sure you want to delete "${domain}"?\n\nThis will remove all associated scan data.`)) {
                return;
            }
            try {
                await apiCall(`/domains/${domain}`, { method: 'DELETE' });
                this.showToast(`Domain "${domain}" deleted successfully`, 'success');
                this.loadDomains();
            } catch (error) {
                this.showToast('Failed to delete domain: ' + error.message, 'error');
            }
        },

        async scanDomain(domain) {
            try {
                const data = await apiCall('/scans', {
                    method: 'POST',
                    body: JSON.stringify({ domain: domain, timeout: 300 })
                });
                this.showToast(`Scan started for "${domain}"`, 'success');
                this.activeTab = 'scans';
                this.loadScans();
                this.startScanPolling(data.scan_id);
            } catch (error) {
                this.showToast('Failed to start scan: ' + error.message, 'error');
            }
        },

        // ============================================
        // Scan Management
        // ============================================

        async loadScans() {
            this.scansLoading = true;
            try {
                const data = await apiCall('/scans?limit=50');
                this.scans = data.scans || [];
                // Start polling for running scans
                this.scans.filter(s => s.status === 'running' || s.status === 'pending').forEach(scan => {
                    this.startScanPolling(scan.scan_id);
                });
            } catch (error) {
                this.showToast('Failed to load scans: ' + error.message, 'error');
                this.scans = [];
            } finally {
                this.scansLoading = false;
            }
        },

        showNewScanModal() {
            this.scanForm = { domain: '', timeout: 300 };
            this.modals.newScan = true;
        },

        async startScan() {
            if (!this.scanForm.domain) {
                this.showToast('Please select a domain', 'warning');
                return;
            }
            try {
                const data = await apiCall('/scans', {
                    method: 'POST',
                    body: JSON.stringify({
                        domain: this.scanForm.domain,
                        timeout: this.scanForm.timeout
                    })
                });
                this.modals.newScan = false;
                this.showToast(`Scan started for "${this.scanForm.domain}"`, 'success');
                this.loadScans();
                this.startScanPolling(data.scan_id);
            } catch (error) {
                this.showToast('Failed to start scan: ' + error.message, 'error');
            }
        },

        async startBatchScan(primaryOnly = false) {
            try {
                const data = await apiCall('/scans/batch', {
                    method: 'POST',
                    body: JSON.stringify({ primary_only: primaryOnly, timeout: 300 })
                });
                if (data.total_queued === 0) {
                    this.showToast('No domains found to scan', 'warning');
                    return;
                }
                this.showToast(data.message, 'success');
                this.loadScans();
                data.scans.forEach(scan => this.startScanPolling(scan.scan_id));
            } catch (error) {
                this.showToast('Failed to start batch scan: ' + error.message, 'error');
            }
        },

        async cancelScan(scanId) {
            if (!confirm('Are you sure you want to cancel this scan?')) return;
            try {
                await apiCall(`/scans/${scanId}/cancel`, { method: 'POST' });
                if (scanPollingIntervals[scanId]) {
                    clearInterval(scanPollingIntervals[scanId]);
                    delete scanPollingIntervals[scanId];
                }
                this.showToast('Scan cancelled', 'success');
                this.loadScans();
            } catch (error) {
                this.showToast('Failed to cancel scan: ' + error.message, 'error');
            }
        },

        async retryScan(scanId) {
            try {
                const data = await apiCall(`/scans/${scanId}/retry`, {
                    method: 'POST',
                    body: JSON.stringify({})
                });
                this.showToast('Scan retry started', 'success');
                this.loadScans();
                this.startScanPolling(data.scan_id);
            } catch (error) {
                this.showToast('Failed to retry scan: ' + error.message, 'error');
            }
        },

        async deleteScan(scanId) {
            if (!confirm('Are you sure you want to delete this scan?\n\nThis will remove all associated findings.')) return;
            try {
                await apiCall(`/scans/${scanId}`, { method: 'DELETE' });
                this.showToast('Scan deleted', 'success');
                this.loadScans();
                this.loadFindings();
                this.loadFindingsStats();
            } catch (error) {
                this.showToast('Failed to delete scan: ' + error.message, 'error');
            }
        },

        startScanPolling(scanId) {
            if (scanPollingIntervals[scanId]) return;
            const self = this;
            scanPollingIntervals[scanId] = setInterval(async () => {
                try {
                    const scan = await apiCall(`/scans/${scanId}`);
                    if (scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled') {
                        clearInterval(scanPollingIntervals[scanId]);
                        delete scanPollingIntervals[scanId];
                        self.loadScans();
                        self.loadFindings();
                        self.loadFindingsStats();
                        if (scan.status === 'completed') {
                            self.showToast(`Scan completed for "${scan.domain}"`, 'success');
                        } else if (scan.status === 'failed') {
                            self.showToast(`Scan failed for "${scan.domain}"`, 'error');
                        } else {
                            self.showToast(`Scan cancelled for "${scan.domain}"`, 'warning');
                        }
                    }
                } catch (error) {
                    console.error('Polling error:', error);
                }
            }, 3000);
        },

        async viewScanResults(scanId) {
            this.scanResultsLoading = true;
            this.scanResults = null;
            this.modals.scanResults = true;
            try {
                this.scanResults = await apiCall(`/scans/${scanId}/results`);
            } catch (error) {
                this.showToast('Failed to load scan results: ' + error.message, 'error');
            } finally {
                this.scanResultsLoading = false;
            }
        },

        // ============================================
        // Findings Management
        // ============================================

        async loadFindings() {
            this.findingsLoading = true;
            try {
                const params = new URLSearchParams({ limit: '100' });
                if (this.severityFilter) params.append('min_severity', this.severityFilter);
                const data = await apiCall(`/findings?${params}`);
                this.findings = data.findings || [];
            } catch (error) {
                this.showToast('Failed to load findings: ' + error.message, 'error');
                this.findings = [];
            } finally {
                this.findingsLoading = false;
            }
        },

        async loadFindingsStats() {
            try {
                const data = await apiCall('/findings/stats');
                this.findingsStats = {
                    critical: data.critical_findings || 0,
                    high: data.high_findings || 0,
                    medium: data.medium_findings || 0,
                    low: data.low_findings || 0,
                    info: data.info_findings || 0
                };
            } catch (error) {
                console.error('Failed to load findings stats:', error);
            }
        },

        async viewFindingDetails(findingId) {
            this.findingDetailsLoading = true;
            this.findingDetails = null;
            this.modals.findingDetails = true;
            try {
                this.findingDetails = await apiCall(`/findings/${findingId}`);
            } catch (error) {
                this.showToast('Failed to load finding details: ' + error.message, 'error');
            } finally {
                this.findingDetailsLoading = false;
            }
        },

        updateFindingStatus(findingId) {
            this.statusUpdateForm = {
                findingId: findingId,
                status: 'new',
                notes: ''
            };
            this.modals.statusUpdate = true;
        },

        async submitStatusUpdate() {
            try {
                await apiCall(`/findings/${this.statusUpdateForm.findingId}`, {
                    method: 'PUT',
                    body: JSON.stringify({
                        status: this.statusUpdateForm.status,
                        resolution_notes: this.statusUpdateForm.notes || null
                    })
                });
                this.modals.statusUpdate = false;
                this.modals.findingDetails = false;
                this.showToast('Finding status updated', 'success');
                this.loadFindings();
                this.loadFindingsStats();
            } catch (error) {
                this.showToast('Failed to update status: ' + error.message, 'error');
            }
        },

        // ============================================
        // Badge Class Helpers
        // ============================================

        getBadgeClass(status) {
            const classes = {
                pending: 'bg-slate-500 text-white',
                running: 'bg-blue-500 text-white animate-pulse',
                completed: 'bg-green-500 text-white',
                failed: 'bg-red-500 text-white',
                cancelled: 'bg-amber-500 text-black'
            };
            return classes[status] || 'bg-slate-500 text-white';
        },

        getSeverityBadgeClass(severity) {
            const classes = {
                critical: 'bg-red-600 text-white',
                high: 'bg-orange-500 text-white',
                medium: 'bg-yellow-500 text-black',
                low: 'bg-green-500 text-white',
                info: 'bg-indigo-500 text-white'
            };
            return classes[severity] || 'bg-slate-500 text-white';
        },

        getStatusBadgeClass(status) {
            const classes = {
                new: 'bg-blue-500 text-white',
                open: 'bg-amber-500 text-black',
                acknowledged: 'bg-indigo-500 text-white',
                resolved: 'bg-green-500 text-white',
                reopened: 'bg-orange-500 text-white',
                false_positive: 'bg-slate-500 text-white'
            };
            return classes[status] || 'bg-slate-500 text-white';
        },

        // ============================================
        // Toast Notifications
        // ============================================

        showToast(message, type = 'info') {
            this.toasts.push({ message, type });
            // Auto-remove after 5 seconds
            setTimeout(() => {
                this.toasts.shift();
            }, 5000);
        },

        removeToast(index) {
            this.toasts.splice(index, 1);
        },

        // ============================================
        // Utility Functions
        // ============================================

        formatDate(dateString) {
            if (!dateString) return 'N/A';
            return new Date(dateString).toLocaleString();
        }
    };
}

// ============================================
// API Helper (standalone function)
// ============================================

async function apiCall(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const defaultOptions = {
        headers: { 'Content-Type': 'application/json' }
    };

    const response = await fetch(url, { ...defaultOptions, ...options });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(error.detail || `HTTP ${response.status}`);
    }

    // Handle 204 No Content
    if (response.status === 204) return null;

    return response.json();
}
