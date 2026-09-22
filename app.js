// ---------------------------------------------------------------------------
// Global CSRF token — read from <meta name="csrf-token"> once at page load.
// ---------------------------------------------------------------------------
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

// ---------------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------------
document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-copy]');
    if (!btn) return;
    const textToCopy = btn.getAttribute('data-copy');
    if (!textToCopy) return;
    
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(textToCopy)
            .then(() => ToastManager.show('Copied!'))
            .catch(() => ToastManager.show('Failed to copy', 'error'));
    } else {
        try {
            const textArea = document.createElement("textarea");
            textArea.value = textToCopy;
            textArea.style.position = "fixed";
            textArea.style.left = "-999999px";
            textArea.style.top = "-999999px";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            const successful = document.execCommand('copy');
            textArea.remove();
            if (successful) ToastManager.show('Copied!');
            else ToastManager.show('Failed to copy', 'error');
        } catch (err) {
            ToastManager.show('Failed to copy', 'error');
        }
    }
});

class ToastManager {
    static show(message, type = 'success') {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' 
            ? `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`
            : `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
            
        toast.innerHTML = `${icon} <span>${message}</span>`;
        container.appendChild(toast);
        
        requestAnimationFrame(() => toast.classList.add('show'));
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
}

// ---------------------------------------------------------------------------
// API helper — all fetches go through here.
// GET requests do NOT send a body; POST requests always include CSRF token.
// ---------------------------------------------------------------------------
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
        },
    };
    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(endpoint, options);
        let resData = {};
        
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            resData = await response.json();
        }

        if (!response.ok) {
            throw { status: response.status, data: resData };
        }
        return resData;
    } catch (err) {
        if (err.data && err.data.error) {
            if (
                endpoint !== '/api/status' &&
                endpoint !== '/api/unlock' &&
                !endpoint.startsWith('/api/jobs/')
            ) {
                ToastManager.show(err.data.message || 'An error occurred', 'error');
            }
            throw err;
        }
        if (endpoint !== '/api/status' && !endpoint.startsWith('/api/jobs/')) {
            ToastManager.show('Network error', 'error');
        }
        throw err;
    }
}

// ---------------------------------------------------------------------------
// Pipeline Trace
// ---------------------------------------------------------------------------
class PipelineTrace {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.stepsContainer = document.getElementById('trace-steps-container');
    }
    
    reset() {
        if (this.stepsContainer) this.stepsContainer.innerHTML = '';
    }

    update(events) {
        if (!this.container || !this.stepsContainer) return;
        this.container.style.display = 'flex';
        
        let html = '';
        events.forEach((ev) => {
            let state = 'pending';
            if (ev.state === 'running') state = 'running';
            else if (ev.state === 'done') state = 'done';
            else if (ev.state === 'failed') state = 'failed';

            let iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`;
            if (state === 'running') {
                iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>`;
            } else if (state === 'done') {
                iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
            } else if (state === 'failed') {
                iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
            }

            html += `
                <div class="trace-step ${state}">
                    <div class="trace-icon">${iconSvg}</div>
                    <div class="trace-content"><div class="trace-title">${ev.detail || ev.step}</div></div>
                </div>
            `;
        });
        this.stepsContainer.innerHTML = html;
    }
}

// ---------------------------------------------------------------------------
// Confetti
// ---------------------------------------------------------------------------
class Confetti {
    static burst() {
        const canvas = document.getElementById('confetti-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        canvas.style.display = 'block';

        const particles = [];
        const colors = ['#22D3EE', '#38BDF8', '#3B82F6', '#34D399', '#FFFFFF'];

        for (let i = 0; i < 150; i++) {
            particles.push({
                x: canvas.width / 2,
                y: canvas.height / 2 + 100,
                r: Math.random() * 6 + 2,
                dx: Math.random() * 20 - 10,
                dy: Math.random() * -20 - 5,
                color: colors[Math.floor(Math.random() * colors.length)],
                tilt: Math.random() * 10,
                tiltAngle: 0,
                tiltAngleInc: (Math.random() * 0.07) + 0.05,
            });
        }

        const render = () => {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            let active = false;
            
            particles.forEach(p => {
                p.tiltAngle += p.tiltAngleInc;
                p.y += (Math.cos(p.tiltAngle) + p.dy + p.r / 2) / 2;
                p.x += Math.sin(p.tiltAngle) * 2 + p.dx;
                p.dy += 0.2; // gravity
                
                if (p.y <= canvas.height) active = true;

                ctx.beginPath();
                ctx.lineWidth = p.r;
                ctx.strokeStyle = p.color;
                ctx.moveTo(p.x + p.tilt + p.r, p.y);
                ctx.lineTo(p.x + p.tilt, p.y + p.tilt + p.r);
                ctx.stroke();
            });

            if (active) {
                requestAnimationFrame(render);
            } else {
                canvas.style.display = 'none';
            }
        };
        render();
    }
}

// ---------------------------------------------------------------------------
// FolderBrowser modal — in-app fallback
// ---------------------------------------------------------------------------
class FolderBrowser {
    constructor() {
        this.modal = document.getElementById('folder-browser-modal');
        this.title = document.getElementById('fb-title');
        this.drivesContainer = document.getElementById('fb-drives');
        this.breadcrumbs = document.getElementById('fb-breadcrumbs');
        this.list = document.getElementById('fb-list');
        this.error = document.getElementById('fb-error');
        this.btnSelect = document.getElementById('btn-fb-select');
        this.btnCancel = document.getElementById('btn-fb-cancel');
        
        this.currentPath = '';
        this.selectedPath = '';
        this.context = '';   // 'encrypt' | 'destination'
        this.type = 'folder'; // 'folder' | 'file'
        
        if (this.btnSelect) {
            this.btnSelect.addEventListener('click', () => this.confirmSelection());
        }
        if (this.btnCancel) {
            this.btnCancel.addEventListener('click', () => this.close());
        }
    }

    open(context, type) {
        this.context = context;
        this.type = type;
        this.title.textContent = type === 'folder' ? 'Choose Folder' : 'Choose File';
        this.btnSelect.textContent = type === 'folder' ? 'Select this folder' : 'Select this file';
        this.btnSelect.disabled = true;
        this.selectedPath = '';
        
        this.modal.classList.add('open');
        this.loadList(); // load root initially
    }

    close() {
        this.modal.classList.remove('open');
    }

    async loadList(path = null) {
        this.list.innerHTML = '<div class="text-muted text-center" style="padding: 24px;">Loading...</div>';
        this.error.textContent = '';
        
        try {
            const url = path
                ? `/api/fs/list?path=${encodeURIComponent(path)}`
                : '/api/fs/list';
            const data = await apiCall(url);
            
            this.currentPath = data.current_path;
            
            // Render drives
            this.drivesContainer.innerHTML = '';
            (data.drives || []).forEach(d => {
                const btn = document.createElement('div');
                btn.className = 'fb-drive';
                btn.textContent = d;
                btn.addEventListener('click', () => this.loadList(d));
                this.drivesContainer.appendChild(btn);
            });

            // Render breadcrumbs
            this.breadcrumbs.innerHTML = '';
            (data.breadcrumbs || []).forEach((crumb, idx) => {
                const span = document.createElement('span');
                span.className = 'fb-crumb';
                span.textContent = crumb.name;
                span.addEventListener('click', () => this.loadList(crumb.path));
                this.breadcrumbs.appendChild(span);
                if (idx < data.breadcrumbs.length - 1) {
                    const sep = document.createElement('span');
                    sep.textContent = ' / ';
                    sep.style.color = 'var(--muted)';
                    this.breadcrumbs.appendChild(sep);
                }
            });
            
            if (!data.readable) {
                this.list.innerHTML = '<div class="text-muted text-center" style="padding: 24px;">Permission denied or folder is unreadable.</div>';
                return;
            }

            // Render items
            this.list.innerHTML = '';
            
            if (data.parent) {
                const row = document.createElement('div');
                row.className = 'fb-row';
                row.innerHTML = `<div class="fb-icon">📁</div><div class="fb-name">..</div>`;
                row.addEventListener('click', () => this.loadList(data.parent));
                this.list.appendChild(row);
            }

            (data.items || []).forEach(item => {
                const row = document.createElement('div');
                row.className = 'fb-row';
                const icon = item.is_dir ? '📁' : '📄';
                const sizeStr = item.size !== null && item.size !== undefined
                    ? formatSize(item.size)
                    : '';
                
                row.innerHTML = `
                    <div class="fb-icon">${icon}</div>
                    <div class="fb-name">${item.name}</div>
                    <div class="fb-size">${sizeStr}</div>
                `;
                
                row.addEventListener('click', () => {
                    // Remove selection from siblings
                    Array.from(this.list.children).forEach(c => c.classList.remove('selected'));
                    
                    if (item.is_dir) {
                        if (this.type === 'folder') {
                            row.classList.add('selected');
                            this.selectedPath = item.path;
                            this.btnSelect.disabled = false;
                        }
                    } else {
                        if (this.type === 'file') {
                            row.classList.add('selected');
                            this.selectedPath = item.path;
                            this.btnSelect.disabled = false;
                        }
                    }
                });

                row.addEventListener('dblclick', () => {
                    if (item.is_dir) {
                        this.loadList(item.path);
                    } else if (this.type === 'file') {
                        this.selectedPath = item.path;
                        this.confirmSelection();
                    }
                });

                this.list.appendChild(row);
            });
            
            // If selecting folder, allow selecting current path if nothing selected
            if (this.type === 'folder' && !this.selectedPath && this.currentPath) {
                this.selectedPath = this.currentPath;
                this.btnSelect.disabled = false;
            }

        } catch (err) {
            this.error.textContent = 'Failed to load directory.';
            this.list.innerHTML = '';
        }
    }

    async confirmSelection() {
        if (!this.selectedPath) return;
        this.close();
        window.appAppManager.onFolderBrowserSelected(this.context, this.selectedPath);
    }
}

// ---------------------------------------------------------------------------
// Shared size formatter
// ---------------------------------------------------------------------------
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ---------------------------------------------------------------------------
// AppManager — the main controller
// ---------------------------------------------------------------------------
class AppManager {
    constructor() {
        this.stepperNodes = document.querySelectorAll('.step');
        
        // Login State
        this.lockoutTimer = null;
        this.pollTimer = null;
        this.unlocked = false;
        
        // Stage 2 State
        this.encryptTarget = null; // path string
        this.storageList = [];
        this.selectedStorageIds = new Set();
        this.storageLoadError = false;
        
        // Stage 3 State
        this.mode = null; // 'encrypt' | 'decrypt'
        this.deleteOriginals = false;
        this.destPath = null;
        this.jobId = null;
        this.jobTimer = null;
        this.pipelineTrace = new PipelineTrace('pipeline-trace');

        // Modals
        this.confirmDeleteModal = document.getElementById('confirm-delete-modal');
        this.folderBrowser = new FolderBrowser();

        // Bind everything via addEventListener — no inline handlers
        try { this.bindLoginEvents(); } catch (e) {
            console.error('bindLoginEvents failed:', e);
            ToastManager.show('UI init error (login)', 'error');
        }
        try { this.bindStage2Events(); } catch (e) {
            console.error('bindStage2Events failed:', e);
            ToastManager.show('UI init error (stage 2)', 'error');
        }
        try { this.bindStage3Events(); } catch (e) {
            console.error('bindStage3Events failed:', e);
            ToastManager.show('UI init error (stage 3)', 'error');
        }
        try { this.bindStage4Events(); } catch (e) {
            console.error('bindStage4Events failed:', e);
            ToastManager.show('UI init error (stage 4)', 'error');
        }
        try { this.bindNavEvents(); } catch (e) {
            console.error('bindNavEvents failed:', e);
        }
        
        this.hlSelectedFile = null;

        this.pollStatus();
    }
    
    // --------------------------------------------------------
    // LOGIN & STATUS
    // --------------------------------------------------------
    bindLoginEvents() {
        const initPass = document.getElementById('init-password');
        if (initPass) initPass.addEventListener('input', () => this.updateStrength());
        
        const btnInit = document.getElementById('btn-init');
        if (btnInit) btnInit.addEventListener('click', () => this.createKeys());
        
        const btnUnlock = document.getElementById('btn-unlock');
        if (btnUnlock) btnUnlock.addEventListener('click', () => this.unlock());
        
        const unlockPass = document.getElementById('unlock-password');
        if (unlockPass) {
            unlockPass.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.unlock();
            });
        }
        
        document.querySelectorAll('.input-icon-toggle').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const input = e.currentTarget.parentElement.querySelector('input');
                if (!input) return;
                if (input.type === 'password') {
                    input.type = 'text';
                    e.currentTarget.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
                } else {
                    input.type = 'password';
                    e.currentTarget.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
                }
            });
        });

        const logoutBtn = document.getElementById('btn-logout');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', async () => {
                const dd = document.getElementById('account-dropdown');
                if (dd) dd.style.display = 'none';
                await apiCall('/api/logout', 'POST');
                this.pollStatus();
            });
        }

        // --- Passphrase Management UI Bindings ---
        const btnAccount = document.getElementById('btn-account-menu');
        if (btnAccount) {
            btnAccount.addEventListener('click', () => {
                const dd = document.getElementById('account-dropdown');
                if (dd) dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
            });
        }
        
        // Hide dropdown on outside click
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#account-dropdown') && !e.target.closest('#btn-account-menu')) {
                const dd = document.getElementById('account-dropdown');
                if (dd) dd.style.display = 'none';
            }
        });

        const btnChangePass = document.getElementById('btn-change-passphrase');
        if (btnChangePass) {
            btnChangePass.addEventListener('click', () => {
                const dd = document.getElementById('account-dropdown');
                if (dd) dd.style.display = 'none';
                document.getElementById('change-old-pass').value = '';
                document.getElementById('change-new-pass').value = '';
                document.getElementById('change-confirm-pass').value = '';
                document.getElementById('change-pass-error').textContent = '';
                this.updateStrength('change-new-pass', 'change-strength-meter');
                document.getElementById('change-passphrase-modal').classList.add('open');
            });
        }

        const changeNewPass = document.getElementById('change-new-pass');
        if (changeNewPass) {
            changeNewPass.addEventListener('input', () => this.updateStrength('change-new-pass', 'change-strength-meter'));
        }

        const btnCancelChange = document.getElementById('btn-cancel-change-pass');
        if (btnCancelChange) {
            btnCancelChange.addEventListener('click', () => {
                document.getElementById('change-passphrase-modal').classList.remove('open');
            });
        }

        const btnSubmitChange = document.getElementById('btn-submit-change-pass');
        if (btnSubmitChange) {
            btnSubmitChange.addEventListener('click', () => this.changePassphrase());
        }

        const linkForgot = document.getElementById('link-forgot-passphrase');
        if (linkForgot) {
            linkForgot.addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('reset-vault-input').value = '';
                document.getElementById('reset-vault-error').textContent = '';
                document.getElementById('btn-confirm-reset-vault').disabled = true;
                document.getElementById('forgot-passphrase-modal').classList.add('open');
            });
        }

        const resetInput = document.getElementById('reset-vault-input');
        if (resetInput) {
            resetInput.addEventListener('input', (e) => {
                const btn = document.getElementById('btn-confirm-reset-vault');
                if (btn) btn.disabled = e.target.value !== 'RESET';
            });
        }

        const btnCancelReset = document.getElementById('btn-cancel-reset-vault');
        if (btnCancelReset) {
            btnCancelReset.addEventListener('click', () => {
                document.getElementById('forgot-passphrase-modal').classList.remove('open');
            });
        }

        const btnConfirmReset = document.getElementById('btn-confirm-reset-vault');
        if (btnConfirmReset) {
            btnConfirmReset.addEventListener('click', () => this.resetVault());
        }
    }

    // --------------------------------------------------------
    // STAGE 2 EVENT BINDINGS
    // --------------------------------------------------------
    bindStage2Events() {
        // Encrypt: native pickers with modal fallback
        const btnFolder = document.getElementById('btn-choose-folder');
        if (btnFolder) {
            btnFolder.addEventListener('click', () => this.openNativePicker('encrypt', 'folder'));
        }

        const btnFile = document.getElementById('btn-choose-file');
        if (btnFile) {
            btnFile.addEventListener('click', () => this.openNativePicker('encrypt', 'file'));
        }

        // Fallback links — open modal directly
        const linkFolder = document.getElementById('link-browse-folder');
        if (linkFolder) {
            linkFolder.addEventListener('click', (e) => {
                e.preventDefault();
                this.folderBrowser.open('encrypt', 'folder');
            });
        }

        const linkFile = document.getElementById('link-browse-file');
        if (linkFile) {
            linkFile.addEventListener('click', (e) => {
                e.preventDefault();
                this.folderBrowser.open('encrypt', 'file');
            });
        }

        // Encrypt Continue
        const btnEncContinue = document.getElementById('btn-stage2-encrypt');
        if (btnEncContinue) {
            btnEncContinue.addEventListener('click', () => this.goToStage3('encrypt'));
        }

        // Decrypt Continue
        const btnDecContinue = document.getElementById('btn-stage2-decrypt');
        if (btnDecContinue) {
            btnDecContinue.addEventListener('click', () => this.goToStage3('decrypt'));
        }

        // Search filter (oninput → addEventListener)
        const searchEl = document.getElementById('storage-search');
        if (searchEl) {
            searchEl.addEventListener('input', () => this.filterStorage());
        }

        // Select-all checkbox
        const selectAll = document.getElementById('storage-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', () => this.toggleSelectAllStorage());
        }

        // Storage list: delegated listener for dynamically-created checkboxes
        const listEl = document.getElementById('storage-list');
        if (listEl) {
            listEl.addEventListener('change', (e) => {
                const cb = e.target;
                if (cb.type === 'checkbox' && cb.dataset.id) {
                    this.toggleStorageSelection(cb.dataset.id, cb.checked);
                }
            });
        }
    }

    // --------------------------------------------------------
    // STAGE 3 EVENT BINDINGS
    // --------------------------------------------------------
    bindStage3Events() {
        const btnStart = document.getElementById('btn-start-job');
        if (btnStart) btnStart.addEventListener('click', () => this.startJob());

        const btnCancel = document.getElementById('btn-cancel-job');
        if (btnCancel) btnCancel.addEventListener('click', () => this.cancelJob());

        const delChk = document.getElementById('delete-originals');
        if (delChk) {
            delChk.addEventListener('change', () => this.handleDeleteToggle(delChk));
        }

        const btnBrowseDest = document.getElementById('btn-browse-dest');
        if (btnBrowseDest) {
            btnBrowseDest.addEventListener('click', () => this.openNativePicker('destination', 'folder'));
        }

        // Delete-modal confirm/cancel
        const btnConfirmDel = document.getElementById('btn-confirm-delete');
        if (btnConfirmDel) {
            btnConfirmDel.addEventListener('click', () => this.confirmDeleteOriginals());
        }
        const btnCancelDel = document.getElementById('btn-cancel-delete');
        if (btnCancelDel) {
            btnCancelDel.addEventListener('click', () => this.cancelDeleteOriginals());
        }
    }

    // --------------------------------------------------------
    // STAGE 4 EVENT BINDINGS
    // --------------------------------------------------------
    bindStage4Events() {
        const btnBack = document.getElementById('btn-back-to-select');
        if (btnBack) btnBack.addEventListener('click', () => this.resetToStage2());

        const btnOpenDest = document.getElementById('btn-open-dest');
        if (btnOpenDest) btnOpenDest.addEventListener('click', () => this.openDestFolder());

        const btnExport = document.getElementById('btn-export-pubkey');
        if (btnExport) btnExport.addEventListener('click', () => this.exportPublicKey());
    }

    // --------------------------------------------------------
    // NAV & NEW FEATURES EVENT BINDINGS
    // --------------------------------------------------------
    bindNavEvents() {
        const btnHash = document.getElementById('nav-btn-hashlab');
        if (btnHash) btnHash.addEventListener('click', () => {
            this.showHashLab();
            this.updateHashText();
            this.updateHashCompare();
        });
        
        const btnVault = document.getElementById('nav-btn-vault');
        if (btnVault) btnVault.addEventListener('click', () => this.showVaultView());

        const btnCloseHash = document.getElementById('btn-close-hashlab');
        if (btnCloseHash) btnCloseHash.addEventListener('click', () => this.goToStage2());

        const btnCloseVault = document.getElementById('btn-close-vault');
        if (btnCloseVault) btnCloseVault.addEventListener('click', () => this.goToStage2());
        
        const btnVerifyAll = document.getElementById('btn-verify-all');
        if (btnVerifyAll) btnVerifyAll.addEventListener('click', () => this.verifyVault());
        
        const hlTextInput = document.getElementById('hl-text-input');
        if (hlTextInput) hlTextInput.addEventListener('input', () => this.updateHashText());
        
        
        const hlCompA = document.getElementById('hl-compare-a');
        const hlCompB = document.getElementById('hl-compare-b');
        if (hlCompA && hlCompB) {
            hlCompA.addEventListener('input', () => this.updateHashCompare());
            hlCompB.addEventListener('input', () => this.updateHashCompare());
        }
        
        const btnHlChooseFile = document.getElementById('btn-hl-choose-file');
        if (btnHlChooseFile) btnHlChooseFile.addEventListener('click', () => this.openNativePicker('hashlab', 'file'));
        
        const btnHlCheckAgain = document.getElementById('btn-hl-check-again');
        if (btnHlCheckAgain) btnHlCheckAgain.addEventListener('click', () => {
            if (this.hlSelectedFile) this.recheckHashLabFile(this.hlSelectedFile);
        });
        
        const btnCloseProof = document.getElementById('btn-close-proof');
        if (btnCloseProof) btnCloseProof.addEventListener('click', () => {
            document.getElementById('proof-modal').classList.remove('open');
        });
        
        // Setup table click delegation for "View Proof" buttons in Vault View
        const vaultTbody = document.getElementById('vault-view-tbody');
        if (vaultTbody) {
            vaultTbody.addEventListener('click', (e) => {
                if (e.target.closest('.btn-view-proof')) {
                    const btn = e.target.closest('.btn-view-proof');
                    const fileId = btn.dataset.id;
                    if (fileId) this.viewProof(fileId);
                }
            });
        }
    }

    showHashLab() {
        document.querySelectorAll('.stage').forEach(el => el.style.display = 'none');
        const panel = document.getElementById('panel-hashlab');
        if (panel) panel.style.display = 'block';
        document.querySelector('.main-layout').classList.remove('has-trace');
        document.querySelector('.right-panel').style.display = 'none';
        this.setStepper(-1); // hide stepper styling
    }

    showVaultView() {
        document.querySelectorAll('.stage').forEach(el => el.style.display = 'none');
        const panel = document.getElementById('panel-vault');
        if (panel) panel.style.display = 'block';
        document.querySelector('.main-layout').classList.remove('has-trace');
        document.querySelector('.right-panel').style.display = 'none';
        this.setStepper(-1);
        
        // Hide verify all results
        document.getElementById('verify-all-results').style.display = 'none';
        
        this.loadVaultView();
    }
    
    async loadVaultView() {
        const tbody = document.getElementById('vault-view-tbody');
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 24px;" class="text-muted">Loading vault entries...</td></tr>';
        
        try {
            const data = await apiCall('/api/files');
            const files = Array.isArray(data.files) ? data.files : [];
            
            tbody.innerHTML = '';
            if (files.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 24px;" class="text-muted">Your vault is empty.</td></tr>';
                return;
            }
            
            files.forEach(f => {
                const tr = document.createElement('tr');
                tr.style.borderBottom = '1px solid var(--glass-border)';
                const size = typeof f.size === 'number' ? formatSize(f.size) : '–';
                
                tr.innerHTML = `
                    <td style="padding: 12px; font-weight: 500;">${f.name}</td>
                    <td style="padding: 12px;" class="monospace text-muted">${f.file_id}</td>
                    <td style="padding: 12px;">${size}</td>
                    <td style="padding: 12px;" class="monospace text-safe">${f.sha256_prefix || ''}...</td>
                    <td style="padding: 12px; text-align: center;">
                        <button class="btn btn-secondary btn-view-proof" data-id="${f.file_id}" style="padding: 4px 8px; font-size: 0.75rem;">View</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } catch (err) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 24px;" class="text-danger">Failed to load vault entries.</td></tr>';
        }
    }

    async viewProof(fileId) {
        try {
            const data = await apiCall(`/api/files/${fileId}/proof`);
            const modal = document.getElementById('proof-modal');
            const body = document.getElementById('proof-card-body');
            
            // Format the proof data nicely
            let html = `
                <div style="background: rgba(4,7,13,0.5); padding: 16px; border-radius: 8px; border: 1px solid var(--glass-border); margin-bottom: 16px;">
                    <h4 style="margin-bottom: 8px; color: var(--cyan);">AES-256 Envelope</h4>
                    <div style="display: grid; grid-template-columns: 100px 1fr; gap: 8px;">
                        <span class="text-muted">IV/Nonce:</span> <span class="monospace" style="word-break: break-all;">${data.aes_iv}</span>
                        <span class="text-muted">Auth Tag:</span> <span class="monospace" style="word-break: break-all;">${data.aes_tag}</span>
                    </div>
                </div>
                
                <div style="background: rgba(4,7,13,0.5); padding: 16px; border-radius: 8px; border: 1px solid var(--glass-border); margin-bottom: 16px;">
                    <h4 style="margin-bottom: 8px; color: var(--blue);">RSA-3072 Protected Key</h4>
                    <div style="display: grid; grid-template-columns: 100px 1fr; gap: 8px;">
                        <span class="text-muted">Key length:</span> <span>${data.encrypted_key_length} bytes</span>
                        <span class="text-muted">Padding:</span> <span>${data.rsa_padding}</span>
                    </div>
                </div>
                
                <div style="background: rgba(4,7,13,0.5); padding: 16px; border-radius: 8px; border: 1px solid var(--glass-border);">
                    <h4 style="margin-bottom: 8px; color: var(--mint);">SHA-256 Integrity</h4>
                    <div style="display: grid; grid-template-columns: 100px 1fr; gap: 8px;">
                        <span class="text-muted">Original File:</span> <span class="monospace" style="word-break: break-all;">${data.original_sha256}</span>
                    </div>
                </div>
            `;
            
            body.innerHTML = html;
            modal.classList.add('open');
        } catch (err) {
            ToastManager.show('Failed to load proof data', 'error');
        }
    }

    async verifyVault() {
        const btn = document.getElementById('btn-verify-all');
        btn.disabled = true;
        btn.textContent = 'Verifying...';
        
        try {
            const data = await apiCall('/api/verify-all', 'POST');
            
            const resultsDiv = document.getElementById('verify-all-results');
            const summaryDiv = document.getElementById('verify-all-summary');
            const tableDiv = document.getElementById('verify-all-table-container');
            
            resultsDiv.style.display = 'block';
            
            if (data.tampered === 0 && data.errors === 0) {
                summaryDiv.innerHTML = `<span class="text-safe" style="font-weight: bold; font-size: 1.1rem;">✓ All ${data.safe} files verified successfully!</span> Vault integrity is intact.`;
                tableDiv.innerHTML = '';
                Confetti.burst();
            } else {
                summaryDiv.innerHTML = `<span class="text-danger" style="font-weight: bold; font-size: 1.1rem;">⚠ Issues Detected:</span> ${data.tampered} tampered, ${data.errors} errors, ${data.safe} safe.`;
                
                // Build failure table
                let tableHtml = `
                    <table style="width: 100%; border-collapse: collapse; font-size: 0.8rem; text-align: left; margin-top: 12px; background: rgba(0,0,0,0.3);">
                        <tr style="border-bottom: 1px solid var(--glass-border);"><th style="padding: 8px;">File</th><th style="padding: 8px;">Issue</th></tr>
                `;
                (data.details || []).filter(d => d.status !== 'SAFE').forEach(d => {
                    tableHtml += `
                        <tr style="border-bottom: 1px solid var(--glass-border);">
                            <td style="padding: 8px; font-weight: 500; color: var(--danger);">${d.name || d.file_id}</td>
                            <td style="padding: 8px;">${d.reason || 'Tampered or Missing'}</td>
                        </tr>
                    `;
                });
                tableHtml += `</table>`;
                tableDiv.innerHTML = tableHtml;
            }
        } catch (err) {
            ToastManager.show('Verification failed to start', 'error');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Verify vault integrity';
        }
    }

    // --- Hash Lab functions ---
    async updateHashText() {
        const input = document.getElementById('hl-text-input').value;
        try {
            const res = await apiCall('/api/hash/text', 'POST', { text: input });
            document.getElementById('hl-text-hash').textContent = res.hash;
            const btnCopy = document.getElementById('btn-hl-copy-hash');
            if (btnCopy) btnCopy.setAttribute('data-copy', res.hash);
        } catch (err) {
            document.getElementById('hl-text-hash').textContent = 'Error computing hash';
            const btnCopy = document.getElementById('btn-hl-copy-hash');
            if (btnCopy) btnCopy.removeAttribute('data-copy');
        }
    }
    
    async updateHashCompare() {
        const textA = document.getElementById('hl-compare-a').value;
        const textB = document.getElementById('hl-compare-b').value;
        
        try {
            const res = await apiCall('/api/hash/compare', 'POST', { text_a: textA, text_b: textB });
            document.getElementById('hl-diff-hash-a').textContent = res.hash_a;
            document.getElementById('hl-diff-hash-b').textContent = res.hash_b;
            
            const bitsChanged = document.getElementById('hl-bits-changed');
            const verdict = document.getElementById('hl-verdict');
            
            bitsChanged.textContent = `${res.bits_changed} of 256 bits changed (about ${Math.round((res.bits_changed / 256) * 100)}%)`;
            
            if (res.hash_a === res.hash_b) {
                verdict.className = 'badge badge-safe';
                verdict.textContent = 'MATCH = SAFE (unchanged)';
                bitsChanged.style.color = 'var(--muted)';
            } else {
                verdict.className = 'badge badge-tampered';
                verdict.textContent = 'MISMATCH = TAMPERED';
                bitsChanged.style.color = 'var(--warn)';
            }
        } catch (err) {
            // silent fail for typing
        }
    }

    async processHashLabFile(path) {
        this.hlSelectedFile = path;
        const infoDiv = document.getElementById('hl-file-info');
        const btnCheck = document.getElementById('btn-hl-check-again');
        
        infoDiv.style.display = 'block';
        document.getElementById('hl-file-name').textContent = path.split(/[\\\\/]/).pop();
        document.getElementById('hl-file-size').textContent = '...';
        document.getElementById('hl-file-initial-hash').textContent = 'Computing...';
        document.getElementById('hl-file-second-box').style.display = 'none';
        
        btnCheck.disabled = true;
        
        try {
            const res = await apiCall('/api/hash/file', 'POST', { path });
            document.getElementById('hl-file-size').textContent = formatSize(res.size);
            document.getElementById('hl-file-initial-hash').textContent = res.hash;
            
            // Set initial state
            document.getElementById('hl-file-initial-hash').dataset.val = res.hash;
            document.getElementById('hl-file-verdict').className = 'badge badge-safe';
            document.getElementById('hl-file-verdict').textContent = 'SAFE';
            
            btnCheck.disabled = false;
        } catch (err) {
            document.getElementById('hl-file-initial-hash').textContent = 'Error computing file hash';
        }
    }
    
    async recheckHashLabFile(path) {
        const btnCheck = document.getElementById('btn-hl-check-again');
        btnCheck.disabled = true;
        btnCheck.textContent = 'Checking...';
        
        document.getElementById('hl-file-second-box').style.display = 'block';
        document.getElementById('hl-file-current-hash').textContent = 'Computing...';
        
        try {
            const res = await apiCall('/api/hash/file', 'POST', { path });
            const currentHash = res.hash;
            const initHash = document.getElementById('hl-file-initial-hash').dataset.val;
            
            document.getElementById('hl-file-current-hash').textContent = currentHash;
            
            const verdict = document.getElementById('hl-file-verdict');
            if (currentHash === initHash) {
                verdict.className = 'badge badge-safe';
                verdict.textContent = 'SAFE (Unchanged)';
                document.getElementById('hl-file-current-hash').style.color = 'var(--mint)';
            } else {
                verdict.className = 'badge badge-tampered';
                verdict.textContent = 'TAMPERED';
                document.getElementById('hl-file-current-hash').style.color = 'var(--danger)';
            }
        } catch (err) {
            document.getElementById('hl-file-current-hash').textContent = 'Error reading file (Deleted or unavailable)';
            const verdict = document.getElementById('hl-file-verdict');
            verdict.className = 'badge badge-tampered';
            verdict.textContent = 'ERROR / MISSING';
        } finally {
            btnCheck.disabled = false;
            btnCheck.textContent = 'Check again';
        }
    }

    // --------------------------------------------------------
    // NATIVE OS PICKER
    // --------------------------------------------------------
    async openNativePicker(context, type) {
        const btnId = context === 'encrypt'
            ? (type === 'folder' ? 'btn-choose-folder' : 'btn-choose-file')
            : 'btn-browse-dest';
        const btn = document.getElementById(btnId);
        const hintEl = document.getElementById('native-dialog-hint');

        // Show spinner on button and hint text
        if (btn) btn.classList.add('loading');
        if (hintEl) hintEl.style.display = 'block';

        try {
            const endpoint = type === 'folder' ? '/api/pick-folder' : '/api/pick-file';
            const result = await apiCall(endpoint, 'POST');

            if (result.fallback) {
                // tkinter unavailable — open in-app modal
                this.folderBrowser.open(context, type);
            } else if (result.path) {
                // User picked something
                await this.onFolderBrowserSelected(context, result.path);
            }
            // else: user cancelled (result.path === null) — do nothing
        } catch (err) {
            // On any error (network, 401 etc.) fall back to in-app browser
            this.folderBrowser.open(context, type);
        } finally {
            if (btn) btn.classList.remove('loading');
            if (hintEl) hintEl.style.display = 'none';
        }
    }

    // --------------------------------------------------------
    // STRENGTH METER
    // --------------------------------------------------------
    updateStrength(inputId = 'init-password', meterId = 'strength-meter') {
        const input = document.getElementById(inputId);
        const meter = document.getElementById(meterId);
        if (!input || !meter) return;
        const val = input.value;
        let score = 0;
        if (val.length >= 10) score++;
        if (val.length > 14) score++;
        if (/[A-Z]/.test(val)) score++;
        if (/[0-9]/.test(val)) score++;
        if (/[^A-Za-z0-9]/.test(val)) score++;
        if (val.length === 0) score = 0;
        else if (val.length < 10) score = 1;
        meter.className = `strength-meter strength-${score}`;
    }

    // --------------------------------------------------------
    // STATUS POLLING
    // --------------------------------------------------------
    async pollStatus() {
        try {
            const data = await apiCall('/api/status', 'GET');
            this.updateHeader(data);
            
            if (!data.unlocked && this.unlocked) {
                this.unlocked = false;
                this.resetToStage1();
            } else if (data.unlocked && !this.unlocked) {
                this.unlocked = true;
                this.goToStage2();
            }

            if (!data.initialized) {
                document.getElementById('init-card').style.display = 'block';
                document.getElementById('unlock-card').style.display = 'none';
            } else if (!data.unlocked) {
                document.getElementById('init-card').style.display = 'none';
                document.getElementById('unlock-card').style.display = 'block';
            }

            if (data.next_delay > 0) this.startLockout(data.next_delay);

        } catch (err) {
            console.error('Failed to poll status', err);
        }
        
        clearTimeout(this.pollTimer);
        this.pollTimer = setTimeout(() => this.pollStatus(), 5000);
    }

    updateHeader(data) {
        const pill = document.getElementById('lock-status');
        const count = document.getElementById('lock-countdown');
        const accountMenu = document.getElementById('btn-account-menu');
        
        if (!pill) return;
        const navHash = document.getElementById('nav-btn-hashlab');
        const navVault = document.getElementById('nav-btn-vault');
        
        if (data.unlocked) {
            pill.className = 'status-pill unlocked';
            pill.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg> Unlocked`;
            if (count) {
                const m = Math.floor(data.seconds_left / 60);
                const s = data.seconds_left % 60;
                count.textContent = `Auto-locks in ${m}:${s.toString().padStart(2, '0')}`;
            }
            if (accountMenu) accountMenu.style.display = 'inline-block';
            if (navHash) navHash.style.display = 'inline-block';
            if (navVault) navVault.style.display = 'inline-block';
        } else {
            pill.className = 'status-pill locked';
            pill.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> Locked`;
            if (count) count.textContent = '';
            if (accountMenu) accountMenu.style.display = 'none';
            if (navHash) navHash.style.display = 'none';
            if (navVault) navVault.style.display = 'none';
        }
        
        const createdEl = document.getElementById('unlock-created-at');
        if (createdEl && data.keys_created_at) {
            const dateStr = new Date(data.keys_created_at).toLocaleDateString();
            createdEl.textContent = `Created on ${dateStr}. Enter it to unlock your vault.`;
        }
    }

    async createKeys() {
        const p1 = document.getElementById('init-password').value;
        const p2 = document.getElementById('init-confirm').value;
        if (p1.length < 10) return ToastManager.show('Passphrase must be at least 10 characters', 'error');
        if (p1 !== p2) return ToastManager.show('Passphrases do not match', 'error');
        
        const btn = document.getElementById('btn-init');
        btn.classList.add('loading');
        try {
            await apiCall('/api/init', 'POST', { passphrase: p1, confirm: p2 });
            ToastManager.show('Keys created securely');
            document.getElementById('init-password').value = '';
            document.getElementById('init-confirm').value = '';
            this.pollStatus();
        } catch (err) {}
        finally { btn.classList.remove('loading'); }
    }

    async unlock() {
        const pass = document.getElementById('unlock-password');
        if (!pass.value) return;
        
        const btn = document.getElementById('btn-unlock');
        const errEl = document.getElementById('unlock-error');
        const card = document.getElementById('unlock-card');
        
        btn.classList.add('loading');
        if (errEl) errEl.textContent = '';
        
        try {
            await apiCall('/api/unlock', 'POST', { passphrase: pass.value });
            pass.value = '';
            ToastManager.show('Vault unlocked');
            
            const icon = document.querySelector('.logo-icon svg');
            if (icon) {
                icon.style.transform = 'scale(1.2)';
                setTimeout(() => icon.style.transform = 'scale(1)', 300);
            }
            this.pollStatus();
        } catch (err) {
            pass.value = '';
            if (card) {
                card.classList.remove('shake');
                void card.offsetWidth;
                card.classList.add('shake');
            }
            if (errEl && err.data && err.data.message) errEl.textContent = err.data.message;
            if (err.data && err.data.next_delay) this.startLockout(err.data.next_delay);
        } finally {
            btn.classList.remove('loading');
        }
    }

    startLockout(seconds) {
        if (this.lockoutTimer) clearInterval(this.lockoutTimer);
        const btn = document.getElementById('btn-unlock');
        if (!btn) return;
        btn.disabled = true;
        let remaining = seconds;
        btn.textContent = `Try again in ${remaining} s`;
        
        this.lockoutTimer = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearInterval(this.lockoutTimer);
                btn.disabled = false;
                btn.textContent = 'Unlock';
            } else {
                btn.textContent = `Try again in ${remaining} s`;
            }
        }, 1000);
    }
    
    async changePassphrase() {
        const oldPass = document.getElementById('change-old-pass').value;
        const newPass = document.getElementById('change-new-pass').value;
        const confirmPass = document.getElementById('change-confirm-pass').value;
        const errEl = document.getElementById('change-pass-error');
        const btn = document.getElementById('btn-submit-change-pass');
        
        if (!oldPass || !newPass || !confirmPass) {
            errEl.textContent = "Please fill in all fields.";
            return;
        }
        
        btn.classList.add('loading');
        errEl.textContent = '';
        
        try {
            await apiCall('/api/change-passphrase', 'POST', {
                old: oldPass,
                new: newPass,
                confirm: confirmPass
            });
            document.getElementById('change-passphrase-modal').classList.remove('open');
            ToastManager.show('Passphrase updated. Your files are unchanged.');
        } catch (err) {
            if (err.data && err.data.message) {
                errEl.textContent = err.data.message;
            } else {
                errEl.textContent = 'Failed to update passphrase.';
            }
            if (err.data && err.data.next_delay) {
                // Not ideal UX, but this forces them out of the modal if locked out
                this.startLockout(err.data.next_delay);
                document.getElementById('change-passphrase-modal').classList.remove('open');
            }
        } finally {
            btn.classList.remove('loading');
        }
    }
    
    async resetVault() {
        const confirm = document.getElementById('reset-vault-input').value;
        const btn = document.getElementById('btn-confirm-reset-vault');
        const errEl = document.getElementById('reset-vault-error');
        
        btn.classList.add('loading');
        errEl.textContent = '';
        
        try {
            await apiCall('/api/reset-vault', 'POST', { confirm });
            document.getElementById('forgot-passphrase-modal').classList.remove('open');
            ToastManager.show('Vault reset. Please create a new passphrase.');
            this.pollStatus();
        } catch (err) {
            if (err.data && err.data.message) {
                errEl.textContent = err.data.message;
            } else {
                errEl.textContent = 'Failed to reset vault.';
            }
        } finally {
            btn.classList.remove('loading');
        }
    }

    // --------------------------------------------------------
    // STAGE NAVIGATION
    // --------------------------------------------------------
    setStepper(stageIdx) {
        this.stepperNodes.forEach((node, i) => {
            node.classList.remove('active', 'completed');
            const nodeCircle = node.querySelector('.step-node');
            if (i < stageIdx) {
                node.classList.add('completed');
                if (nodeCircle) {
                    nodeCircle.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
                }
            } else if (i === stageIdx) {
                node.classList.add('active');
                if (nodeCircle) {
                    nodeCircle.textContent = String(i + 1);
                }
            } else {
                if (nodeCircle) {
                    nodeCircle.textContent = String(i + 1);
                }
            }
        });
    }

    showStage(num) {
        document.querySelectorAll('.stage').forEach(el => el.style.display = 'none');
        const st = document.getElementById(`stage-${num}`);
        if (st) st.style.display = 'block';
        this.setStepper(num - 1);

        const mainLayout = document.querySelector('.main-layout');
        const rightPanel = document.querySelector('.right-panel');
        const traceCard = document.getElementById('pipeline-trace');

        if (num === 3 || num === 4) {
            if (mainLayout) mainLayout.classList.add('has-trace');
            if (rightPanel) rightPanel.style.display = 'block';
            if (traceCard) traceCard.style.display = 'flex';
        } else {
            if (mainLayout) mainLayout.classList.remove('has-trace');
            if (rightPanel) rightPanel.style.display = 'none';
            if (traceCard) traceCard.style.display = 'none';
        }
    }

    resetToStage1() {
        this.showStage(1);
    }

    goToStage2() {
        this.showStage(2);
        try {
            this.loadStorage();
        } catch (e) {
            console.error('loadStorage error:', e);
            ToastManager.show('Failed to refresh vault list', 'error');
        }
    }

    goToStage3(mode) {
        this.mode = mode;
        this.showStage(3);
        
        const title = document.getElementById('stage3-title');
        const desc = document.getElementById('stage3-desc');
        const encOpts = document.getElementById('stage3-encrypt-opts');
        const decOpts = document.getElementById('stage3-decrypt-opts');
        
        document.getElementById('job-progress-container').style.display = 'none';
        document.getElementById('btn-start-job').style.display = 'block';
        document.getElementById('btn-cancel-job').disabled = false;
        
        this.pipelineTrace.reset();

        if (mode === 'encrypt') {
            title.textContent = 'Ready to Encrypt';
            const count = document.getElementById('preview-count').textContent;
            const size = document.getElementById('preview-size').textContent;
            desc.textContent = `Encrypting ${count} items (${size}) into your vault.`;
            encOpts.style.display = 'block';
            decOpts.style.display = 'none';
        } else {
            title.textContent = 'Ready to Decrypt';
            desc.textContent = `Extracting ${this.selectedStorageIds.size} files from your vault.`;
            encOpts.style.display = 'none';
            decOpts.style.display = 'block';
            
            if (!this.destPath) {
                document.getElementById('btn-start-job').disabled = true;
            }
        }
    }

    resetToStage2() {
        this.jobId = null;
        this.deleteOriginals = false;
        const delChk = document.getElementById('delete-originals');
        if (delChk) delChk.checked = false;
        document.getElementById('encrypt-preview').style.display = 'none';
        document.getElementById('btn-stage2-encrypt').disabled = true;
        
        document.getElementById('result-encrypt').style.display = 'none';
        document.getElementById('result-decrypt').style.display = 'none';
        document.getElementById('tampered-banner').style.display = 'none';
        document.getElementById('btn-open-dest').style.display = 'none';
        
        this.goToStage2();
    }

    // --------------------------------------------------------
    // FOLDER BROWSER CALLBACK
    // --------------------------------------------------------
    async onFolderBrowserSelected(context, path) {
        if (context === 'encrypt') {
            this.encryptTarget = path;
            const disp = document.getElementById('encrypt-path-display');
            disp.textContent = path;
            document.getElementById('encrypt-preview').style.display = 'block';
            
            // Animate counters while loading
            document.getElementById('preview-count').textContent = '…';
            document.getElementById('preview-size').textContent = '…';
            
            try {
                const data = await apiCall('/api/fs/preview', 'POST', { path });
                // Animate count
                this._animateCount('preview-count', data.file_count);
                document.getElementById('preview-size').textContent = formatSize(data.total_size);
                document.getElementById('preview-items-label').textContent = data.file_count === 1 ? 'item' : 'items';
                
                const skipEl = document.getElementById('preview-skipped');
                if (data.skipped_symlinks > 0) {
                    skipEl.style.display = 'inline-flex';
                    skipEl.textContent = `${data.skipped_symlinks} skipped symlinks`;
                } else {
                    skipEl.style.display = 'none';
                }
                
                document.getElementById('btn-stage2-encrypt').disabled = false;
            } catch (err) {
                disp.textContent = 'Failed to preview path.';
                document.getElementById('preview-count').textContent = '–';
                document.getElementById('preview-size').textContent = '–';
            }
        } else if (context === 'destination') {
            this.destPath = path;
            document.getElementById('dest-path').textContent = path;
            document.getElementById('btn-start-job').disabled = false;
        } else if (context === 'hashlab') {
            this.processHashLabFile(path);
        }
    }

    _animateCount(elId, target) {
        const el = document.getElementById(elId);
        if (!el) return;
        let current = 0;
        const step = Math.max(1, Math.ceil(target / 20));
        const iv = setInterval(() => {
            current = Math.min(current + step, target);
            el.textContent = current;
            if (current >= target) clearInterval(iv);
        }, 30);
    }

    // --------------------------------------------------------
    // STORAGE / DECRYPT LIST
    // --------------------------------------------------------
    async loadStorage() {
        const listEl = document.getElementById('storage-list');
        listEl.innerHTML = '<div class="text-muted" style="text-align: center; padding: 24px;">Loading...</div>';
        this.storageLoadError = false;

        try {
            const data = await apiCall('/api/files');
            // Server returns {"files": [...]}
            const files = Array.isArray(data.files) ? data.files : [];
            this.storageList = files;
            this.selectedStorageIds.clear();
            this.renderStorageList(files);
        } catch (err) {
            this.storageLoadError = true;
            listEl.innerHTML = `
                <div style="text-align: center; padding: 24px;">
                    <div class="text-danger" style="margin-bottom: 8px;">Failed to load vault list.</div>
                    <button id="btn-retry-storage" class="btn btn-secondary" style="font-size: 0.875rem; padding: 6px 16px;">Retry</button>
                </div>
            `;
            const retryBtn = document.getElementById('btn-retry-storage');
            if (retryBtn) {
                retryBtn.addEventListener('click', () => this.loadStorage());
            }
        }
    }

    renderStorageList(files) {
        const listEl = document.getElementById('storage-list');
        listEl.innerHTML = '';
        if (files.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 32px;">
                    <div style="font-size: 2rem; margin-bottom: 8px;">🔒</div>
                    <div class="text-muted">Nothing encrypted yet.</div>
                    <div class="text-muted" style="font-size: 0.8rem; margin-top: 4px;">Use the Encrypt card to add files.</div>
                </div>
            `;
            document.getElementById('btn-stage2-decrypt').disabled = true;
            // 3b: disable and uncheck select-all when vault is empty
            const selAll = document.getElementById('storage-select-all');
            if (selAll) { selAll.disabled = true; selAll.checked = false; }
            return;
        }
        
        files.forEach(f => {
            const row = document.createElement('div');
            row.className = 'storage-row';
            
            const isChecked = this.selectedStorageIds.has(f.file_id) ? 'checked' : '';
            const name = f.name || f.file_id;
            const hashPrefix = f.sha256_prefix || '';
            const size = typeof f.size === 'number' ? formatSize(f.size) : '–';
            // created_at is stored as an ISO string, e.g. "2026-09-21T08:00:00+00:00"
            const date = f.created_at
                ? new Date(f.created_at).toLocaleDateString()
                : '';
            
            // NOTE: onchange is NOT used here; event delegation is on #storage-list
            row.innerHTML = `
                <input type="checkbox" data-id="${f.file_id}" ${isChecked}>
                <div class="storage-name" title="${name}">
                    ${name}
                    <div style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--muted); opacity: 0.7;">${hashPrefix}</div>
                </div>
                <div class="storage-size">${size}</div>
                <div class="storage-date">${date}</div>
            `;
            listEl.appendChild(row);
        });
        // Enable/disable select-all based on whether list has items
        const selAll = document.getElementById('storage-select-all');
        if (selAll) {
            selAll.disabled = false;
        }
        this.updateDecryptButton();
    }

    filterStorage() {
        const query = document.getElementById('storage-search').value.toLowerCase();
        const filtered = this.storageList.filter(f =>
            (f.name || '').toLowerCase().includes(query)
        );
        this.renderStorageList(filtered);
    }

    toggleStorageSelection(id, isChecked) {
        if (isChecked) this.selectedStorageIds.add(id);
        else this.selectedStorageIds.delete(id);
        this.updateDecryptButton();
        this.updateSelectAllCheckbox();
    }

    toggleSelectAllStorage() {
        const chk = document.getElementById('storage-select-all');
        const query = document.getElementById('storage-search').value.toLowerCase();
        const visibleFiles = this.storageList.filter(f =>
            (f.name || '').toLowerCase().includes(query)
        );
        
        if (chk.checked) {
            visibleFiles.forEach(f => this.selectedStorageIds.add(f.file_id));
        } else {
            visibleFiles.forEach(f => this.selectedStorageIds.delete(f.file_id));
        }
        this.renderStorageList(visibleFiles);
    }

    updateDecryptButton() {
        const btn = document.getElementById('btn-stage2-decrypt');
        if (btn) btn.disabled = this.selectedStorageIds.size === 0;
    }
    
    updateSelectAllCheckbox() {
        const query = document.getElementById('storage-search').value.toLowerCase();
        const visibleFiles = this.storageList.filter(f =>
            (f.name || '').toLowerCase().includes(query)
        );
        const allSelected = visibleFiles.length > 0 &&
            visibleFiles.every(f => this.selectedStorageIds.has(f.file_id));
        const chk = document.getElementById('storage-select-all');
        if (chk) chk.checked = allSelected;
    }

    // --------------------------------------------------------
    // OPTIONS & MODALS
    // --------------------------------------------------------
    handleDeleteToggle(el) {
        if (el.checked) {
            this.confirmDeleteModal.classList.add('open');
        } else {
            this.deleteOriginals = false;
        }
    }

    confirmDeleteOriginals() {
        this.deleteOriginals = true;
        this.confirmDeleteModal.classList.remove('open');
    }

    cancelDeleteOriginals() {
        this.deleteOriginals = false;
        const chk = document.getElementById('delete-originals');
        if (chk) chk.checked = false;
        this.confirmDeleteModal.classList.remove('open');
    }

    // --------------------------------------------------------
    // JOB EXECUTION
    // --------------------------------------------------------
    async startJob() {
        document.getElementById('btn-start-job').style.display = 'none';
        document.getElementById('job-progress-container').style.display = 'block';
        document.getElementById('job-progress-bar').style.width = '0%';
        document.getElementById('job-percent').textContent = '0%';
        
        const lockInPlaceEl = document.getElementById('lock-in-place');
        const lockInPlace = lockInPlaceEl ? lockInPlaceEl.checked : false;

        const payload = this.mode === 'encrypt' 
            ? { path: this.encryptTarget, delete_originals: this.deleteOriginals, lock_in_place: lockInPlace }
            : { file_ids: Array.from(this.selectedStorageIds), dest: this.destPath };
            
        const endpoint = this.mode === 'encrypt' ? '/api/encrypt' : '/api/decrypt';
        
        try {
            const data = await apiCall(endpoint, 'POST', payload);
            this.jobId = data.job_id;
            this.pollJob();
        } catch (err) {
            document.getElementById('btn-start-job').style.display = 'block';
            document.getElementById('job-progress-container').style.display = 'none';
        }
    }

    async pollJob() {
        if (!this.jobId) return;
        
        try {
            const data = await apiCall(`/api/jobs/${this.jobId}`);
            
            // update progress
            const pct = Math.floor(data.progress * 100);
            document.getElementById('job-progress-bar').style.width = `${pct}%`;
            document.getElementById('job-percent').textContent = `${pct}%`;
            
            const stateLabel = {
                'pending': 'Waiting...',
                'running': 'Processing...',
                'done':    'Complete',
                'failed':  'Failed',
                'cancelled': 'Cancelled',
            };
            document.getElementById('job-status-text').textContent =
                stateLabel[data.state] || data.state;
            
            // update trace
            if (data.events) {
                if (data.state === 'done') {
                    data.events.forEach(e => {
                        if (e.state === 'running') e.state = 'done';
                    });
                }
                this.pipelineTrace.update(data.events);
            }

            if (data.state === 'done') {
                this.jobId = null;
                setTimeout(() => this.showResults(data.results), 500);
            } else if (data.state === 'failed') {
                this.jobId = null;
                document.getElementById('job-status-text').textContent =
                    data.error || 'Job failed';
                document.getElementById('job-progress-bar').style.background = 'var(--danger)';
            } else if (data.state === 'cancelled') {
                this.jobId = null;
                document.getElementById('job-status-text').textContent =
                    'Cancelled — nothing was changed';
                document.getElementById('job-progress-bar').style.background = 'var(--muted)';
                setTimeout(() => this.resetToStage2(), 2000);
            } else {
                this.jobTimer = setTimeout(() => this.pollJob(), 300);
            }
        } catch (err) {
            console.error(err);
            this.jobTimer = setTimeout(() => this.pollJob(), 2000);
        }
    }

    async cancelJob() {
        if (this.jobId) {
            try {
                await apiCall(`/api/jobs/${this.jobId}/cancel`, 'POST');
                const btnCancel = document.getElementById('btn-cancel-job');
                if (btnCancel) {
                    btnCancel.disabled = true;
                    btnCancel.textContent = 'Cancelling...';
                }
            } catch (err) {}
        } else {
            this.resetToStage2();
        }
    }

    // --------------------------------------------------------
    // STAGE 4: RESULTS
    // --------------------------------------------------------
    showResults(resultData) {
        this.showStage(4);
        if (this.mode === 'encrypt') {
            document.getElementById('result-encrypt').style.display = 'block';
            const r = resultData || {};
            document.getElementById('res-enc-count').textContent = r.encrypted ?? r.encrypted_count ?? 0;
            document.getElementById('res-enc-skip').textContent =
                Array.isArray(r.skipped) ? r.skipped.length : (r.skipped_count ?? 0);
            document.getElementById('res-enc-err').textContent =
                Array.isArray(r.errors) ? r.errors.length : (r.error_count ?? 0);
            
            if (document.getElementById('res-enc-removed')) {
                document.getElementById('res-enc-removed').textContent = (r.originals_removed ?? 0) + (r.locked_in_place ?? 0);
            }
            if (document.getElementById('res-enc-kept')) {
                const keptCount = Array.isArray(r.originals_kept) ? r.originals_kept.length : (r.originals_kept ?? 0);
                document.getElementById('res-enc-kept').textContent = keptCount;
                const keptList = document.getElementById('res-enc-keptlist');
                if (keptList && keptCount > 0) {
                    keptList.style.display = 'block';
                    keptList.innerHTML = '<strong>Kept Originals:</strong><ul style="margin-top: 8px; margin-left: 20px;">' + 
                        (Array.isArray(r.originals_kept) ? r.originals_kept : []).map(e => `<li>${e}</li>`).join('') + '</ul>';
                } else if (keptList) {
                    keptList.style.display = 'none';
                }
            }
            
            const errList = document.getElementById('res-enc-errlist');
            const errArr = Array.isArray(r.errors) ? r.errors : [];
            if (errArr.length > 0) {
                errList.style.display = 'block';
                errList.innerHTML = '<strong>Errors:</strong><ul style="margin-top: 8px; margin-left: 20px;">' + 
                    errArr.map(e => `<li>${e}</li>`).join('') + '</ul>';
            } else {
                errList.style.display = 'none';
            }
            
            const errCount = Array.isArray(r.errors) ? r.errors.length : (r.error_count ?? 0);
            if (errCount === 0) Confetti.burst();
            
        } else {
            document.getElementById('result-decrypt').style.display = 'block';
            document.getElementById('btn-open-dest').style.display = 'inline-block';
            
            const tbody = document.getElementById('res-dec-tbody');
            tbody.innerHTML = '';
            
            const files = Array.isArray(resultData) ? resultData : (resultData?.files || []);
            let anyTampered = false;
            
            files.forEach(f => {
                const tr = document.createElement('tr');
                const name = f.name || (f.dest_path ? f.dest_path.split(/[\\/]/).pop() : f.file_id);
                if (f.status === 'SAFE') {
                    tr.innerHTML = `
                        <td style="font-weight: 500;">${name}</td>
                        <td><div class="badge badge-safe">SAFE</div></td>
                        <td class="monospace text-muted" style="font-size: 0.8rem; word-break: break-all;">
                            ${f.expected_hash || ''}
                            <button class="btn btn-secondary" style="padding: 2px 6px; font-size: 0.7rem; margin-left: 4px;" data-copy="${f.expected_hash || ''}">Copy</button>
                        </td>
                        <td class="text-safe" style="font-size: 0.8rem;">Verified and extracted</td>
                    `;
                } else {
                    anyTampered = true;
                    tr.style.background = 'rgba(239, 68, 68, 0.08)';
                    tr.innerHTML = `
                        <td style="font-weight: 500; color: var(--danger);">${name}</td>
                        <td><div class="badge badge-tampered">TAMPERED</div></td>
                        <td class="monospace text-muted" style="font-size: 0.8rem;">Exp: ${(f.expected_hash || '').substring(0,8)}...<br>Got: ${(f.actual_hash || '').substring(0,8)}...</td>
                        <td class="text-danger" style="font-size: 0.8rem;">${f.reason || ''}</td>
                    `;
                }
                tbody.appendChild(tr);
            });
            
            const banner = document.getElementById('tampered-banner');
            if (anyTampered) {
                banner.style.display = 'block';
            } else {
                banner.style.display = 'none';
                Confetti.burst();
            }
        }
    }
    
    async exportPublicKey() {
        window.location.href = '/api/export-pubkey';
    }
    
    async openDestFolder() {
        if (this.destPath) {
            try {
                await apiCall('/api/open-folder', 'POST', { path: this.destPath });
            } catch (err) {}
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap on DOMContentLoaded
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.appAppManager = new AppManager();
    } catch (err) {
        console.error('Cryptix failed to start:', err);
        // Show a visible error card in the normal style
        const errorHtml = `
            <div style="
                position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%);
                background: rgba(9, 17, 29, 0.97);
                border: 1px solid rgba(239, 68, 68, 0.5);
                border-radius: 12px; padding: 32px; max-width: 480px; width: 90%;
                text-align: center; z-index: 9999;
                box-shadow: 0 0 40px rgba(239, 68, 68, 0.2);
            ">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none"
                     stroke="#EF4444" stroke-width="2" style="margin-bottom: 16px;">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <h2 style="color: #EF4444; margin-bottom: 12px;">Could not load Cryptix</h2>
                <p style="color: #94A3B8; margin-bottom: 20px; font-size: 0.9rem;">
                    ${String(err).replace(/</g, '&lt;').replace(/>/g, '&gt;')}
                </p>
                <button id="btn-startup-retry"
                    style="
                        background: linear-gradient(135deg, #06B6D4, #3B82F6);
                        color: #04070D; border: none; border-radius: 8px;
                        padding: 12px 24px; font-size: 1rem; font-weight: 600;
                        cursor: pointer;
                    ">
                    Retry
                </button>
            </div>
        `;
        const overlay = document.createElement('div');
        overlay.innerHTML = errorHtml;
        document.body.appendChild(overlay);
        const retryBtn = document.getElementById('btn-startup-retry');
        if (retryBtn) {
            retryBtn.addEventListener('click', () => window.location.reload());
        }
    }
});
