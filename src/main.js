import './style.css';
import { SecureCrypto } from './crypto.js';
import { DB } from './db.js';
import { jsPDF } from 'jspdf';


// DOM Elements
const fileList = document.getElementById('file-list');
const addFileBtn = document.getElementById('add-file-btn');
const addModal = document.getElementById('add-modal');
const authModal = document.getElementById('auth-modal');
const viewer = document.getElementById('viewer');
const fileInput = document.getElementById('file-input');
const privacyCurtain = document.getElementById('privacy-curtain');

// Feature Elements
const themeToggle = document.getElementById('theme-toggle');
const searchInput = document.getElementById('search-input');
const sortSelect = document.getElementById('sort-select');
const storageText = document.getElementById('storage-text');
const storageFill = document.getElementById('storage-fill');
const bulkActions = document.getElementById('bulk-actions');
const selectedCount = document.getElementById('selected-count');
const bulkDeleteBtn = document.getElementById('bulk-delete-btn');
const cancelSelectBtn = document.getElementById('cancel-select-btn');
const infoModal = document.getElementById('info-modal');
const renameModal = document.getElementById('rename-modal');
const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');

// New Feature Elements

const exportAllBtn = document.getElementById('export-all-btn');
const bulkExportBtn = document.getElementById('bulk-export-btn');
const recentSection = document.getElementById('recent-section');
const recentScroll = document.getElementById('recent-scroll');
const dropZone = document.getElementById('drop-zone');
const statTotal = document.getElementById('stat-total');
const statImages = document.getElementById('stat-images');
const statVideos = document.getElementById('stat-videos');
const statSize = document.getElementById('stat-size');
const settingsModal = document.getElementById('settings-modal');
const changePassModal = document.getElementById('change-pass-modal');
const noteModal = document.getElementById('note-modal');
const settingsBtn = document.getElementById('settings-btn');
const helpBtn = document.getElementById('help-btn');
const helpModal = document.getElementById('help-modal');

// State
let selectedFileForAuth = null;
let currentDecryptedUrl = null;
let currentViewOnceId = null;
let allFiles = [];
let selectedFiles = new Set();
let currentRenameFileId = null;
let currentInfoFileId = null;
let recentlyViewed = JSON.parse(localStorage.getItem('sv_recent') || '[]');
let autoLockTimer = null;
let isGridView = false;
let currentChangePassFileId = null;
let currentNoteFileId = null;
let currentShareFileId = null;
let failedAttempts = {};
let appLockPassword = localStorage.getItem('sv_app_lock') || null;
// State variables for removed settings are no longer needed
// let privacyBlur = localStorage.getItem('sv_privacy_blur') !== 'false';
// let showExtensions = localStorage.getItem('sv_show_ext') !== 'false';
// let reducedMotion = localStorage.getItem('sv_motion') === 'true';
// let isCompact = localStorage.getItem('sv_compact') === 'true';
// let hideThumbnails = localStorage.getItem('sv_hide_thumbs') === 'true';

// Keeping these as default values in code if they are referenced elsewhere, or removing them completely if safely possible.
// For now, I will hardcode values where they were used, or let's see. 
// Actually, it's cleaner to remove them and update logic to behave as "standard" (true/false) where appropriate.

// Re-evaluating: The user wants to REMOVE the features. 
// "Show File Extensions" removed -> implies default behavior (show or hide?). Usually show is better or just filename as is.
// "Compact View" removed -> implies standard view.
// "Hide File Icons" removed -> implies show icons.
// "Reduced Motion" removed -> implies animations enabled.
// "Privacy Curtain" removed -> implies no blur on tab switch.

// So I won't define them as variables. I'll just remove the lines.
let autoLockTimeout = parseInt(localStorage.getItem('sv_autolock') || '300000');

// --- Mobile-Friendly Custom Dialogs ---

/**
 * Custom prompt dialog (mobile-friendly replacement for browser prompt())
 * @param {string} title - Dialog title
 * @param {string} message - Description message
 * @param {Object} options - Optional settings { inputType: 'text'|'password', placeholder: string }
 * @returns {Promise<string|null>} - User input or null if cancelled
 */
function showPrompt(title, message = '', options = {}) {
  return new Promise((resolve) => {
    const modal = document.getElementById('custom-prompt-modal');
    const titleEl = document.getElementById('prompt-title');
    const messageEl = document.getElementById('prompt-message');
    const inputEl = document.getElementById('prompt-input');
    const confirmBtn = document.getElementById('prompt-confirm');
    const cancelBtn = document.getElementById('prompt-cancel');

    titleEl.textContent = title;
    messageEl.textContent = message;
    inputEl.type = options.inputType || 'text';
    inputEl.placeholder = options.placeholder || 'Enter value...';
    inputEl.value = '';

    const cleanup = () => {
      modal.close();
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      inputEl.onkeydown = null;
    };

    confirmBtn.onclick = () => {
      const value = inputEl.value;
      cleanup();
      resolve(value || null);
    };

    cancelBtn.onclick = () => {
      cleanup();
      resolve(null);
    };

    inputEl.onkeydown = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        confirmBtn.click();
      }
    };

    modal.showModal();
    setTimeout(() => inputEl.focus(), 100);
  });
}

/**
 * Custom confirm dialog (mobile-friendly replacement for browser confirm())
 * @param {string} title - Dialog title
 * @param {string} message - Confirmation message
 * @returns {Promise<boolean>} - true if confirmed, false if cancelled
 */
function showConfirm(title, message = '') {
  return new Promise((resolve) => {
    const modal = document.getElementById('custom-confirm-modal');
    const titleEl = document.getElementById('confirm-title');
    const messageEl = document.getElementById('confirm-message');
    const okBtn = document.getElementById('confirm-ok');
    const cancelBtn = document.getElementById('confirm-cancel');

    titleEl.textContent = title;
    messageEl.textContent = message;

    let resolved = false;

    const cleanup = () => {
      modal.close();
      okBtn.onclick = null;
      cancelBtn.onclick = null;
      modal.removeEventListener('click', backdropHandler);
      modal.removeEventListener('close', closeHandler);
    };

    const backdropHandler = (event) => {
      // If click is on the modal backdrop (not the content)
      if (event.target === modal && !resolved) {
        resolved = true;
        cleanup();
        resolve(false);
      }
    };

    const closeHandler = () => {
      // Handle ESC key or other close methods
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve(false);
      }
    };

    okBtn.onclick = () => {
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve(true);
      }
    };

    cancelBtn.onclick = () => {
      if (!resolved) {
        resolved = true;
        cleanup();
        resolve(false);
      }
    };

    modal.addEventListener('click', backdropHandler);
    modal.addEventListener('close', closeHandler);

    modal.showModal();
  });
}

/**
 * Custom alert dialog (mobile-friendly replacement for browser alert())
 * @param {string} title - Dialog title
 * @param {string} message - Alert message
 * @returns {Promise<void>}
 */
function showAlert(title, message = '') {
  return new Promise((resolve) => {
    const modal = document.getElementById('custom-alert-modal');
    const titleEl = document.getElementById('alert-title');
    const messageEl = document.getElementById('alert-message');
    const okBtn = document.getElementById('alert-ok');

    titleEl.textContent = title;
    messageEl.textContent = message;

    const cleanup = () => {
      modal.close();
      okBtn.onclick = null;
    };

    okBtn.onclick = () => {
      cleanup();
      resolve();
    };

    modal.showModal();
  });
}

// --- Initialization ---

async function init() {
  checkAppLock();
  loadTheme();
  loadSettings();
  checkExpiredFiles(); // Auto-delete expired files
  await renderFileList();
  setupEventListeners();
  checkCrashRecovery();
  renderRecentlyViewed();
  startAutoLockTimer();
  updatePanicVisibility(); // Initial check
}

init();

// --- Event Listeners ---

function setupEventListeners() {
  addFileBtn.addEventListener('click', () => addModal.showModal());
  document.getElementById('cancel-add').addEventListener('click', () => {
    addModal.close();
    resetAddForm();
  });
  document.getElementById('confirm-add').addEventListener('click', handleAddFile);

  document.getElementById('cancel-auth').addEventListener('click', () => {
    authModal.close();
    document.getElementById('auth-password').value = '';
    selectedFileForAuth = null;
  });
  document.getElementById('confirm-auth').addEventListener('click', handleAuthSubmit);
  document.getElementById('close-viewer').addEventListener('click', closeViewer);

  // Feature Listeners
  themeToggle?.addEventListener('click', toggleTheme);
  searchInput?.addEventListener('input', handleSearch);
  sortSelect?.addEventListener('change', handleSort);
  document.getElementById('new-password')?.addEventListener('input', updatePasswordStrength);

  // Bulk Actions
  bulkDeleteBtn?.addEventListener('click', handleBulkDelete);
  bulkExportBtn?.addEventListener('click', handleBulkExport);
  cancelSelectBtn?.addEventListener('click', cancelBulkSelect);

  // Modals
  document.getElementById('close-info')?.addEventListener('click', () => infoModal.close());
  document.getElementById('cancel-rename')?.addEventListener('click', () => renameModal.close());
  document.getElementById('confirm-rename')?.addEventListener('click', handleRename);



  // Export All
  exportAllBtn?.addEventListener('click', handleExportAll);

  // Drag & Drop
  setupDragDrop();

  // Keyboard Shortcuts
  setupKeyboardShortcuts();

  // Auto-lock reset on activity
  ['click', 'keydown', 'scroll', 'touchstart'].forEach(event => {
    document.addEventListener(event, resetAutoLockTimer, { passive: true });
  });

  // Help Modal
  helpBtn?.addEventListener('click', () => helpModal?.showModal());
  document.getElementById('close-help')?.addEventListener('click', () => helpModal?.close());

  // Click outside modal to close (backdrop click)
  setupModalBackdropClose();

  // Settings Modal
  settingsBtn?.addEventListener('click', () => {
    loadSettings();
    settingsModal?.showModal();
  });
  document.getElementById('close-settings')?.addEventListener('click', () => settingsModal?.close());

  document.getElementById('set-app-lock')?.addEventListener('click', handleSetAppLock);
  document.getElementById('remove-app-lock')?.addEventListener('click', handleRemoveAppLock);

  document.getElementById('feedback-btn')?.addEventListener('click', () => {
    const email = "coralgenz@zohomail.in";
    const subject = encodeURIComponent("SecureVault Feedback");
    const body = encodeURIComponent("Hi team,\n\nI have some feedback for SecureVault:\n");

    // Attempt to open mail client
    window.location.href = `mailto:${email}?subject=${subject}&body=${body}`;

    // Optional: You could show a toast here, but mailto action is usually immediate.
  });



  // Panic Button Listeners
  document.getElementById('panic-btn')?.addEventListener('click', triggerPanic);
  document.getElementById('panic-action-select')?.addEventListener('change', async (e) => {
    const newValue = e.target.value;
    const oldValue = localStorage.getItem('sv_panic_action') || 'blur';

    // Ask for confirmation
    const confirmed = await showConfirm('Change Panic Action', `Set panic action to "${e.target.options[e.target.selectedIndex].text}"?`);

    if (confirmed) {
      localStorage.setItem('sv_panic_action', newValue);
      await showAlert('Saved', 'Panic button action updated.');
    } else {
      // Revert to old value
      e.target.value = oldValue;
    }
  });

  // Panic Enable Toggle
  document.getElementById('panic-enable-toggle')?.addEventListener('change', (e) => {
    const isEnabled = e.target.checked;
    localStorage.setItem('sv_panic_enabled', isEnabled);
    updatePanicVisibility();
    if (isEnabled) {
      showAlert('Panic Button Enabled', 'The panic button is now visible in the header.');
    }
  });

  // Settings Toggles Removed

  document.getElementById('clear-all-btn')?.addEventListener('click', clearAllData);
  document.getElementById('auto-lock-time')?.addEventListener('change', updateAutoLockTime);

  // Change Password Modal
  document.getElementById('cancel-change-pass')?.addEventListener('click', () => changePassModal?.close());
  document.getElementById('confirm-change-pass')?.addEventListener('click', handleChangePassword);

  // Note Modal
  document.getElementById('cancel-note')?.addEventListener('click', () => noteModal?.close());
  document.getElementById('confirm-note')?.addEventListener('click', handleSaveNote);

  // Share Modal
  const shareModal = document.getElementById('share-modal');
  document.getElementById('cancel-share')?.addEventListener('click', () => shareModal?.close());
  document.getElementById('confirm-share')?.addEventListener('click', handleShareConfirm);

  document.getElementById('share-logo')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    const textEl = document.getElementById('share-logo-text');
    if (textEl) {
      textEl.textContent = file ? file.name : 'Choose File';
    }
  });

  // Security Monitoring (Privacy Curtain Removed as per request)
  // document.addEventListener('visibilitychange', handleVisibilityChange);
  // window.addEventListener('blur', () => enablePrivacyCurtain());
  // window.addEventListener('focus', () => disablePrivacyCurtain());

  // File Upload Zone - Show preview when file selected
  fileInput?.addEventListener('change', handleFileSelect);

  // File remove button
  document.getElementById('file-remove-btn')?.addEventListener('click', removeSelectedFile);

  // Drag over effects for upload zone
  const uploadZone = document.getElementById('file-upload-zone');
  uploadZone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('drag-over');
  });
  uploadZone?.addEventListener('dragleave', () => {
    uploadZone.classList.remove('drag-over');
  });
  uploadZone?.addEventListener('drop', () => {
    uploadZone.classList.remove('drag-over');
  });

  // Prevent Screenshots/Context Menu
  document.addEventListener('contextmenu', e => e.preventDefault());
  document.addEventListener('keydown', e => {
    if (e.key === 'PrintScreen' || (e.ctrlKey && e.key === 'p')) {
      e.preventDefault();
      alert('Screenshots are disabled');
    }
  });
}

function resetAddForm() {
  fileInput.value = '';
  document.getElementById('new-password').value = '';
  document.getElementById('expiry-date').value = '';
  document.getElementById('file-note').value = '';
  strengthBar.className = 'strength-bar';
  strengthText.innerText = 'Enter a password';

  // Reset file preview
  const uploadZone = document.getElementById('file-upload-zone');
  const filePreview = document.getElementById('file-preview');
  uploadZone?.classList.remove('hidden');
  filePreview?.classList.add('hidden');
}

// --- Feature: File Upload Preview ---
function handleFileSelect() {
  const file = fileInput.files[0];
  if (!file) return;

  const uploadZone = document.getElementById('file-upload-zone');
  const filePreview = document.getElementById('file-preview');
  const filePreviewName = document.getElementById('file-preview-name');
  const filePreviewSize = document.getElementById('file-preview-size');

  // Update preview info
  filePreviewName.textContent = file.name;
  filePreviewSize.textContent = formatFileSize(file.size);

  // Show preview, hide upload zone
  uploadZone?.classList.add('hidden');
  filePreview?.classList.remove('hidden');
}

function removeSelectedFile(e) {
  e.preventDefault();
  e.stopPropagation();

  fileInput.value = '';

  const uploadZone = document.getElementById('file-upload-zone');
  const filePreview = document.getElementById('file-preview');

  uploadZone?.classList.remove('hidden');
  filePreview?.classList.add('hidden');
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// --- Feature: Click Outside Modal to Close ---
function setupModalBackdropClose() {
  // Get all dialog modals
  const modals = document.querySelectorAll('dialog.modal');

  modals.forEach(modal => {
    modal.addEventListener('click', (e) => {
      // Check if click is on the dialog backdrop (not on modal-content)
      const rect = modal.getBoundingClientRect();
      const isInDialog = (
        e.clientX >= rect.left &&
        e.clientX <= rect.right &&
        e.clientY >= rect.top &&
        e.clientY <= rect.bottom
      );

      // If click is on the backdrop area (the dialog element itself, not its content)
      if (e.target === modal) {
        modal.close();

        // Reset add form if it's the add modal
        if (modal.id === 'add-modal') {
          resetAddForm();
        }
      }
    });
  });
}

// --- Feature: Theme Toggle ---
function loadTheme() {
  const saved = localStorage.getItem('sv_theme');
  if (saved === 'light') document.body.classList.add('light-theme');
}

function toggleTheme() {
  document.body.classList.toggle('light-theme');
  const isLight = document.body.classList.contains('light-theme');
  localStorage.setItem('sv_theme', isLight ? 'light' : 'dark');
}

// --- Feature: Password Strength ---
function updatePasswordStrength() {
  const pwd = document.getElementById('new-password').value;
  let strength = 0;
  if (pwd.length >= 6) strength++;
  if (pwd.length >= 10) strength++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) strength++;
  if (/[0-9]/.test(pwd)) strength++;
  if (/[^A-Za-z0-9]/.test(pwd)) strength++;

  strengthBar.className = 'strength-bar';
  if (strength <= 1) { strengthBar.classList.add('weak'); strengthText.innerText = 'Weak'; }
  else if (strength === 2) { strengthBar.classList.add('fair'); strengthText.innerText = 'Fair'; }
  else if (strength === 3) { strengthBar.classList.add('good'); strengthText.innerText = 'Good'; }
  else { strengthBar.classList.add('strong'); strengthText.innerText = 'Strong 💪'; }
}

// --- Feature: Search ---
function handleSearch() {
  const query = searchInput.value.toLowerCase().trim();
  renderFileList(query);
}

// --- Feature: Sort ---
function handleSort() {
  renderFileList(searchInput?.value || '');
}

// --- Feature: Storage Usage & Stats ---
function updateStorageUsage(files) {
  const totalSize = files.reduce((sum, f) => sum + (f.size || 0), 0);
  const sizeMB = (totalSize / 1024 / 1024).toFixed(2);
  storageText.innerText = `${files.length} files • ${sizeMB} MB used`;
  const percent = Math.min((totalSize / (500 * 1024 * 1024)) * 100, 100);
  storageFill.style.width = percent + '%';

  // Update stats dashboard
  const images = files.filter(f => f.type?.startsWith('image')).length;
  const videos = files.filter(f => f.type?.startsWith('video')).length;
  if (statTotal) statTotal.innerText = files.length;
  if (statImages) statImages.innerText = images;
  if (statVideos) statVideos.innerText = videos;
  if (statSize) statSize.innerText = sizeMB;
}

// --- Feature: Bulk Select ---
function updateBulkUI() {
  if (selectedFiles.size > 0) {
    bulkActions.classList.remove('hidden');
    selectedCount.innerText = `${selectedFiles.size} selected`;
  } else {
    bulkActions.classList.add('hidden');
  }
}

function cancelBulkSelect() {
  selectedFiles.clear();
  updateBulkUI();
  renderFileList(searchInput?.value || '');
}

async function handleBulkDelete() {
  const confirmed = await showConfirm('Delete Files', `Delete ${selectedFiles.size} file(s)? This cannot be undone.`);
  if (!confirmed) return;
  for (const id of selectedFiles) {
    await DB.deleteFile(id);
  }
  selectedFiles.clear();
  updateBulkUI();
  renderFileList();
  await showAlert('Success', 'Files deleted.');
}

async function handleBulkExport() {
  if (selectedFiles.size === 0) return;
  await showAlert('Export', `Exporting ${selectedFiles.size} files. Each will download separately.`);
  for (const id of selectedFiles) {
    const fileRecord = await DB.getFile(id);
    if (fileRecord) {
      // Trigger share for each
      await handleShareFileById(id);
    }
  }
  selectedFiles.clear();
  updateBulkUI();
  renderFileList();
}

// Helper for export by ID
async function handleShareFileById(fileId) {
  const fileRecord = await DB.getFile(fileId);
  if (!fileRecord) return;
  const result = await decryptFileForExport(fileRecord);
  if (!result || !result.buffer) return;
  const { buffer: decryptedBuffer, password: capturedPassword } = result;

  // Prompt for the original password to use for the export only if we don't have it
  let finalPassword = capturedPassword;
  if (!finalPassword) {
    finalPassword = await showPrompt('Share File', `Enter the file's password to protect this export:`, { inputType: 'password', placeholder: 'Enter original password...' });
  }
  if (!finalPassword) return;

  const exportSalt = SecureCrypto.generateSalt();
  const exportKey = await SecureCrypto.deriveKeyFromPassword(finalPassword, exportSalt);
  const { iv, ciphertext } = await SecureCrypto.encryptData(exportKey, decryptedBuffer);

  const blobToBase64 = (blob) => new Promise((resolve) => {
    const reader = new FileReader();
    reader.readAsDataURL(blob);
    reader.onloadend = () => resolve(reader.result.split(',')[1]);
  });

  const base64Data = await blobToBase64(new Blob([ciphertext]));
  const { header, footer } = generateSecureHTMLParts(fileRecord, exportSalt, iv);
  const finalBlob = new Blob([header, base64Data, footer], { type: 'text/html' });
  const url = URL.createObjectURL(finalBlob);

  const a = document.createElement('a');
  a.href = url;
  a.download = fileRecord.name + '.secure.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}



// --- Feature: Export All ---
async function handleExportAll() {
  const files = await DB.getAllFiles();
  if (files.length === 0) {
    await showAlert('No Files', 'No files to export.');
    return;
  }
  const confirmed = await showConfirm('Export All', `Export all ${files.length} files? Each will download separately.`);
  if (!confirmed) return;

  for (const file of files) {
    await handleShareFileById(file.id);
  }
  await showAlert('Success', 'All files exported!');
}

// --- Feature: Drag & Drop ---
function setupDragDrop() {
  const app = document.getElementById('app');

  ['dragenter', 'dragover'].forEach(eventName => {
    app?.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone?.classList.remove('hidden');
      dropZone?.classList.add('active');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    app?.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone?.classList.add('hidden');
      dropZone?.classList.remove('active');
    });
  });

  app?.addEventListener('drop', async (e) => {
    e.preventDefault();
    const files = e.dataTransfer?.files;
    if (files && files.length > 0) {
      for (const file of files) {
        await addFileFromDrop(file);
      }
    }
  });
}

async function addFileFromDrop(file) {
  const password = await showPrompt('Set Password', `Set password for: ${file.name}`, { inputType: 'password', placeholder: 'Enter secure password...' });
  if (!password) return;

  const fileKey = await SecureCrypto.generateKey();
  const salt = SecureCrypto.generateSalt();
  const passwordKey = await SecureCrypto.deriveKeyFromPassword(password, salt);
  const fileBuffer = await file.arrayBuffer();
  const { iv: fileIv, ciphertext } = await SecureCrypto.encryptData(fileKey, fileBuffer);
  const { iv: wrapIv, wrappedData: wrappedWithPass } = await SecureCrypto.wrapKey(fileKey, passwordKey);

  const fileRecord = {
    id: crypto.randomUUID(),
    name: file.name,
    type: file.type,
    size: file.size,
    date: Date.now(),
    authMode: 'always',
    keys: [{ type: 'password', salt, iv: wrapIv, data: wrappedWithPass }],
    content: ciphertext,
    iv: fileIv,
    viewCount: 0
  };

  await DB.saveFile(fileRecord);
  renderFileList();
  await showAlert('Success', `${file.name} encrypted and saved!`);
}

// --- Feature: Keyboard Shortcuts ---
function setupKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + N = New file
    if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
      e.preventDefault();
      addModal.showModal();
    }
    // Ctrl/Cmd + F = Focus search
    if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
      e.preventDefault();
      searchInput?.focus();
    }
    // Escape = Close modals
    if (e.key === 'Escape') {
      addModal.close();
      authModal.close();
      infoModal?.close();
      renameModal?.close();
    }
    // Ctrl/Cmd + T = Toggle theme
    if ((e.ctrlKey || e.metaKey) && e.key === 't') {
      e.preventDefault();
      toggleTheme();
    }
  });
}

// --- Feature: Auto-Lock Timer ---
// --- Feature: Auto-Lock Timer (Configurable) ---
function startAutoLockTimer() {
  resetAutoLockTimer();
}

function resetAutoLockTimer() {
  if (autoLockTimer) clearTimeout(autoLockTimer);
  if (autoLockTimeout > 0) {
    autoLockTimer = setTimeout(triggerAutoLock, autoLockTimeout);
  }
}

function triggerAutoLock() {
  closeViewer();
  if (appLockPassword) {
    checkAppLock();
  } else {
    // Fallback if no password set but timeout reached
    location.reload();
  }
}

function updateAutoLockTime() {
  const select = document.getElementById('auto-lock-time');
  autoLockTimeout = parseInt(select?.value || '300000');
  localStorage.setItem('sv_autolock', autoLockTimeout);
  resetAutoLockTimer();
}

// --- Feature: Auto-Delete Expired Files ---
async function checkExpiredFiles() {
  const files = await DB.getAllFiles();
  const now = Date.now();
  let deleted = 0;

  for (const file of files) {
    if (file.expiryDate && new Date(file.expiryDate).getTime() < now) {
      await DB.deleteFile(file.id);
      deleted++;
    }
  }

  if (deleted > 0) {
    console.log(`Auto-deleted ${deleted} expired file(s)`);
  }
}

// --- Feature: Failed Attempts Lockout ---
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 5 * 60 * 1000; // 5 minutes

function checkFileLocked(fileId) {
  const attempt = failedAttempts[fileId];
  if (attempt && attempt.locked && Date.now() < attempt.lockedUntil) {
    const remaining = Math.ceil((attempt.lockedUntil - Date.now()) / 1000);
    alert(`File locked. Try again in ${remaining} seconds.`);
    return true;
  }
  return false;
}

function recordFailedAttempt(fileId) {
  if (!failedAttempts[fileId]) {
    failedAttempts[fileId] = { count: 0, locked: false, lockedUntil: 0 };
  }
  failedAttempts[fileId].count++;

  const attemptsLeft = MAX_ATTEMPTS - failedAttempts[fileId].count;
  const attemptsEl = document.getElementById('attempts-left');
  const warningEl = document.getElementById('auth-attempts');

  if (attemptsLeft <= 3) {
    warningEl?.classList.remove('hidden');
    if (attemptsEl) attemptsEl.innerText = attemptsLeft;
  }

  if (failedAttempts[fileId].count >= MAX_ATTEMPTS) {
    failedAttempts[fileId].locked = true;
    failedAttempts[fileId].lockedUntil = Date.now() + LOCKOUT_DURATION;
    authModal.close();
    alert('Too many failed attempts. File locked for 5 minutes.');
  }
}

function clearFailedAttempts(fileId) {
  delete failedAttempts[fileId];
  document.getElementById('auth-attempts')?.classList.add('hidden');
}

// --- Feature: Change Password ---
function openChangePasswordModal(e, fileId, fileName) {
  e.stopPropagation();
  currentChangePassFileId = fileId;
  document.getElementById('change-pass-file').innerText = fileName;
  document.getElementById('current-password').value = '';
  document.getElementById('new-password-change').value = '';
  document.getElementById('confirm-password-change').value = '';
  changePassModal?.showModal();
}

async function handleChangePassword() {
  const currentPass = document.getElementById('current-password').value;
  const newPass = document.getElementById('new-password-change').value;
  const confirmPass = document.getElementById('confirm-password-change').value;

  if (!currentPass || !newPass || !confirmPass) {
    await showAlert('Required', 'Please fill all fields');
    return;
  }

  if (newPass !== confirmPass) {
    await showAlert('Error', 'New passwords do not match');
    return;
  }

  if (newPass.length < 4) {
    await showAlert('Error', 'New password must be at least 4 characters');
    return;
  }

  try {
    const file = await DB.getFile(currentChangePassFileId);
    if (!file) throw new Error('File not found');

    const passKeyEntry = file.keys.find(k => k.type === 'password');
    if (!passKeyEntry) throw new Error('No password key found');

    // Verify current password
    const currentPasswordKey = await SecureCrypto.deriveKeyFromPassword(currentPass, passKeyEntry.salt);
    const fileKey = await SecureCrypto.unwrapKey(passKeyEntry.data, currentPasswordKey, passKeyEntry.iv);

    // Create new password wrapper
    const newSalt = SecureCrypto.generateSalt();
    const newPasswordKey = await SecureCrypto.deriveKeyFromPassword(newPass, newSalt);
    const { iv: newWrapIv, wrappedData: newWrappedKey } = await SecureCrypto.wrapKey(fileKey, newPasswordKey);

    // Update file
    file.keys = file.keys.filter(k => k.type !== 'password');
    file.keys.push({ type: 'password', salt: newSalt, iv: newWrapIv, data: newWrappedKey });

    // Add to access log
    file.accessLog = file.accessLog || [];
    file.accessLog.push({ action: 'password_changed', date: Date.now() });

    await DB.updateFile(file);
    changePassModal?.close();
    await showAlert('Success', 'Password changed successfully!');

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Failed to change password. Current password may be incorrect.');
  }
}

// --- Feature: File Notes ---
function openNoteModal(e, fileId, currentNote) {
  e.stopPropagation();
  currentNoteFileId = fileId;
  document.getElementById('edit-note').value = currentNote || '';
  noteModal?.showModal();
}

async function handleSaveNote() {
  const note = document.getElementById('edit-note').value.trim();

  try {
    const file = await DB.getFile(currentNoteFileId);
    if (file) {
      file.note = note;
      await DB.updateFile(file);
    }
    noteModal?.close();
    renderFileList(searchInput?.value || '');
  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Failed to save note');
  }
}

// --- Feature: Duplicate File ---
async function duplicateFile(e, fileId) {
  e.stopPropagation();

  try {
    const file = await DB.getFile(fileId);
    if (!file) return;

    const newFile = {
      ...file,
      id: crypto.randomUUID(),
      name: file.name + ' (Copy)',
      date: Date.now(),
      accessLog: [{ action: 'created_copy', date: Date.now() }]
    };

    await DB.saveFile(newFile);
    renderFileList();
    await showAlert('Success', 'File duplicated!');
  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Failed to duplicate file');
  }
}

// --- Feature: Access Log ---
function addAccessLog(file, action) {
  file.accessLog = file.accessLog || [];
  file.accessLog.push({ action, date: Date.now() });
  if (file.accessLog.length > 20) {
    file.accessLog = file.accessLog.slice(-20);
  }
}

// --- Feature: Decoy Password ---
function saveDecoyPassword() {
  const pass = document.getElementById('decoy-password').value;
  if (!pass) {
    localStorage.removeItem('sv_decoy');
    decoyPassword = null;
    showAlert('Removed', 'Decoy password removed');
  } else {
    localStorage.setItem('sv_decoy', pass);
    decoyPassword = pass;
    showAlert('Saved', 'Decoy password saved! Using this password will show an empty vault.');
  }
  document.getElementById('decoy-password').value = '';
}

// --- Feature: Clear All Data ---
async function clearAllData() {
  const confirmed1 = await showConfirm('⚠️ WARNING', 'This will delete ALL encrypted files permanently! Are you sure?');
  if (!confirmed1) return;

  const confirmed2 = await showConfirm('Final Warning', 'This action CANNOT be undone.');
  if (!confirmed2) return;

  const confirmation = await showPrompt('Confirm Delete', 'Type DELETE to confirm:', { placeholder: 'DELETE' });
  if (confirmation !== 'DELETE') {
    await showAlert('Cancelled', 'Operation cancelled.');
    return;
  }

  try {
    const files = await DB.getAllFiles();
    for (const file of files) {
      await DB.deleteFile(file.id);
    }
    localStorage.removeItem('sv_recent');
    recentlyViewed = [];
    settingsModal?.close();
    renderFileList();
    await showAlert('Success', 'All data has been cleared.');
  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Error clearing data');
  }
}

// --- Feature: Recently Viewed ---
function addToRecentlyViewed(file) {
  recentlyViewed = recentlyViewed.filter(r => r.id !== file.id);
  recentlyViewed.unshift({ id: file.id, name: file.name, type: file.type, date: Date.now() });
  if (recentlyViewed.length > 5) recentlyViewed = recentlyViewed.slice(0, 5);
  localStorage.setItem('sv_recent', JSON.stringify(recentlyViewed));
  renderRecentlyViewed();
}

function renderRecentlyViewed() {
  if (!recentSection || !recentScroll) return;

  // Filter out files that no longer exist
  const validRecent = recentlyViewed.filter(r => allFiles.some(f => f.id === r.id));

  if (validRecent.length === 0) {
    recentSection.classList.add('hidden');
    return;
  }

  recentSection.classList.remove('hidden');
  recentScroll.innerHTML = validRecent.map(r => `
    <div class="recent-item" data-id="${r.id}">
      <span>${r.type?.startsWith('image') ? '🖼️' : r.type?.startsWith('video') ? '🎬' : '📄'}</span>
      <span>${r.name}</span>
    </div>
  `).join('');

  recentScroll.querySelectorAll('.recent-item').forEach(el => {
    el.onclick = () => onFileClick(el.dataset.id);
  });
}

// --- Feature: Delete Single File ---
async function handleDeleteFile(e, fileId) {
  e.stopPropagation();
  const confirmed = await showConfirm('Delete File', 'Delete this file permanently?');
  if (!confirmed) return;
  await DB.deleteFile(fileId);
  renderFileList();
}

// --- Feature: File Info ---
async function showFileInfo(e, fileId) {
  e.stopPropagation();
  const file = allFiles.find(f => f.id === fileId);
  if (!file) return;

  document.getElementById('info-name').innerText = file.name;
  document.getElementById('info-type').innerText = file.type || 'Unknown';
  document.getElementById('info-size').innerText = (file.size / 1024 / 1024).toFixed(2) + ' MB';
  document.getElementById('info-date').innerText = new Date(file.date).toLocaleDateString();
  document.getElementById('info-mode').innerText = file.authMode;

  // New fields
  const expiresEl = document.getElementById('info-expires');
  if (expiresEl) {
    expiresEl.innerText = file.expiryDate ? new Date(file.expiryDate).toLocaleString() : 'Never';
  }

  const viewsEl = document.getElementById('info-views');
  if (viewsEl) {
    viewsEl.innerText = file.viewCount || 0;
  }

  const noteEl = document.getElementById('info-note');
  if (noteEl) {
    noteEl.innerText = file.note || '-';
  }

  // Access Log
  const logEl = document.getElementById('access-log');
  if (logEl && file.accessLog && file.accessLog.length > 0) {
    logEl.innerHTML = file.accessLog.slice(-10).reverse().map(log => `
      <div class="access-log-item">
        ${log.action.replace('_', ' ')} - ${new Date(log.date).toLocaleString()}
      </div>
    `).join('');
  } else if (logEl) {
    logEl.innerHTML = 'No access history';
  }

  infoModal.showModal();
}

// --- Feature: Rename ---
function openRenameModal(e, fileId, currentName) {
  e.stopPropagation();
  currentRenameFileId = fileId;
  const input = document.getElementById('rename-input');
  input.value = currentName;
  renameModal.showModal();
  setTimeout(() => {
    input.focus();
    input.select();
  }, 100);
}

async function handleRename() {
  const newName = document.getElementById('rename-input').value.trim();
  if (!newName || !currentRenameFileId) return;

  const file = await DB.getFile(currentRenameFileId);
  if (file) {
    file.name = newName;
    await DB.updateFile(file);
  }
  renameModal.close();
  currentRenameFileId = null;
  renderFileList();
}

// --- Feature: Favorites ---
async function toggleFavorite(e, fileId) {
  e.stopPropagation();
  const file = await DB.getFile(fileId);
  if (file) {
    file.favorite = !file.favorite;
    await DB.updateFile(file);
    renderFileList(searchInput?.value || '');
  }
}

// --- Logic: Import / Share ---


async function handleShareFile(e, fileId) {
  e.stopPropagation();

  try {
    const fileRecord = await DB.getFile(fileId);
    if (!fileRecord) return;

    const result = await decryptFileForExport(fileRecord);
    if (!result || !result.buffer) return;
    const { buffer: decryptedBuffer, password: capturedPassword } = result;

    let finalPassword = capturedPassword;
    if (!finalPassword) {
      // If we didn't capture the password (e.g. Persistent mode used device key), we must ask for it now
      finalPassword = await showPrompt('Share File', `Enter the file's password to protect this export:`, { inputType: 'password', placeholder: 'Enter original password...' });
    }

    if (!finalPassword) return;

    // Simple share without customization
    await exportSecureFile(fileRecord, decryptedBuffer, finalPassword, {});

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Share failed: ' + err.message);
  }
}

// Open Share Modal
function handleCustomShare(e, fileId) {
  e.stopPropagation();
  currentShareFileId = fileId;
  document.getElementById('share-password').value = '';
  document.getElementById('share-title').value = '';
  document.getElementById('share-logo').value = '';
  const shareModal = document.getElementById('share-modal');
  shareModal?.showModal();
}

// Handle Export from Modal
async function handleShareConfirm() {
  const shareModal = document.getElementById('share-modal');
  const password = document.getElementById('share-password').value;
  const title = document.getElementById('share-title').value || 'SecureVault';
  const logoInput = document.getElementById('share-logo');

  if (!password) {
    await showAlert('Required', 'Please set a password for the file.');
    return;
  }

  const confirmBtn = document.getElementById('confirm-share');
  const originalText = confirmBtn.innerText;
  confirmBtn.innerText = 'Exporting...';

  try {
    const fileRecord = await DB.getFile(currentShareFileId);
    if (!fileRecord) throw new Error('File not found');

    const result = await decryptFileForExport(fileRecord, password);
    if (!result || !result.buffer) throw new Error('Decryption failed');
    const decryptedBuffer = result.buffer;

    // Process Logo
    let logoDataUrl = "";
    if (logoInput.files && logoInput.files[0]) {
      logoDataUrl = await new Promise(resolve => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.readAsDataURL(logoInput.files[0]);
      });
    }

    const customization = { title: title, logoUrl: logoDataUrl };
    await exportSecureFile(fileRecord, decryptedBuffer, password, customization);

    shareModal.close();
    currentShareFileId = null;

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Export failed: ' + err.message);
  } finally {
    confirmBtn.innerText = originalText;
  }
}

// Common export function
async function exportSecureFile(fileRecord, decryptedBuffer, password, customization) {
  const exportSalt = SecureCrypto.generateSalt();
  const exportKey = await SecureCrypto.deriveKeyFromPassword(password, exportSalt);
  const { iv, ciphertext } = await SecureCrypto.encryptData(exportKey, decryptedBuffer);

  const blobToBase64 = (blob) => {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.readAsDataURL(blob);
      reader.onloadend = () => {
        resolve(reader.result.split(',')[1]);
      };
    });
  };

  const base64Data = await blobToBase64(new Blob([ciphertext]));
  const { header, footer } = generateSecureHTMLParts(fileRecord, exportSalt, iv, customization);

  const finalBlob = new Blob([header, base64Data, footer], { type: 'text/html' });
  const url = URL.createObjectURL(finalBlob);

  const a = document.createElement('a');
  a.href = url;
  a.download = fileRecord.name + '.secure.html';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  await showAlert('Success', 'Exported! The file is password-protected.');
}

// Generate Header and Footer parts for the HTML wrapper to allow efficient Blob assembly
function generateSecureHTMLParts(fileMeta, salt, iv, customization = {}) {
  // Buffers to Base64
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const saltB64 = toB64(salt);
  const ivB64 = toB64(iv);

  // Customization defaults
  const brandTitle = customization.title || 'SecureVault';
  const logoUrl = customization.logoUrl || '';

  // Logo HTML - either custom image or default lock icon
  const logoHTML = logoUrl
    ? `<img src="${logoUrl}" alt="Logo" style="width:64px;height:64px;object-fit:contain;margin-bottom:16px;border-radius:12px;">`
    : `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:#0f172a;margin-bottom:16px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`;

  const header = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${brandTitle} - ${fileMeta.name}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:#ffffff;color:#0f172a;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:24px}
        .container{background:#ffffff;padding:48px 32px;border-radius:16px;text-align:center;box-shadow:0 4px 6px -1px rgba(0,0,0,0.07),0 2px 4px -2px rgba(0,0,0,0.07);max-width:400px;width:100%;border:1px solid #e5e5e5}
        .brand{font-size:14px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px}
        h2{font-size:20px;font-weight:600;margin-bottom:8px;color:#0f172a}
        .filename{font-size:14px;color:#64748b;margin-bottom:24px;word-break:break-all}
        #input-area{display:flex;flex-direction:column;gap:12px}
        input{width:100%;padding:14px 16px;border-radius:8px;border:1px solid #e5e5e5;background:#fafafa;color:#0f172a;font-size:14px;font-family:inherit;outline:none;transition:border-color 0.2s,background 0.2s}
        input:focus{border-color:#a3a3a3;background:#ffffff}
        input::placeholder{color:#a3a3a3}
        button{background:#0f172a;color:#ffffff;border:none;padding:14px 24px;border-radius:8px;font-weight:600;font-size:14px;cursor:pointer;width:100%;font-family:inherit;transition:background 0.2s}
        button:hover{background:#1e293b}
        button:active{transform:scale(0.98)}
        #error{color:#dc2626;margin-top:12px;font-size:13px;display:none}
        #status{color:#64748b;margin-top:12px;font-size:12px;min-height:1.2em}
        #viewer{width:100%;height:100%;display:none;flex-direction:column;align-items:center;justify-content:center;position:fixed;top:0;left:0;background:#ffffff;z-index:9999;padding:24px}
        video,audio,img{max-width:100%;max-height:80vh;border-radius:12px;box-shadow:0 20px 25px -5px rgba(0,0,0,0.1),0 8px 10px -6px rgba(0,0,0,0.1)}
        .expired-msg{color:#dc2626;font-size:24px;font-weight:700;margin-bottom:12px}
        .close-btn{position:absolute;top:20px;right:20px;background:#f5f5f5;color:#0f172a;border:1px solid #e5e5e5;padding:10px 20px;border-radius:8px;font-weight:500;cursor:pointer;font-family:inherit}
        .close-btn:hover{background:#e5e5e5}
        .badge{display:inline-block;padding:4px 12px;background:#f5f5f5;border-radius:100px;font-size:11px;font-weight:600;color:#64748b;margin-bottom:16px;text-transform:uppercase;letter-spacing:0.02em}
        .badge.view-once{background:#fef2f2;color:#dc2626}
        .footer{margin-top:32px;font-size:11px;color:#a3a3a3}
    </style>
</head>
<body>
    <div id="auth" class="container">
        ${logoHTML}
        <div class="brand">${brandTitle}</div>
        <h2>Secure File</h2>
        <p class="filename">${fileMeta.name}</p>
        ${fileMeta.authMode === 'view-once' ? '<span class="badge view-once">View Once</span>' : ''}
        ${fileMeta.expiryDate ? '<span class="badge">Expires ' + new Date(fileMeta.expiryDate).toLocaleDateString() + '</span>' : ''}
        
        <div id="input-area">
            <input type="password" id="pwd" placeholder="Enter password" autofocus>
            <button onclick="unlock()">Unlock File</button>
        </div>
        
        <p id="error">Incorrect password</p>
        <p id="status"></p>
        <p class="footer">Protected by ${brandTitle}</p>
    </div>
    
    <div id="viewer"></div>

    <script>
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('keydown', e => {
            if (e.key === 'PrintScreen' || (e.ctrlKey && e.key === 'p') || (e.ctrlKey && e.shiftKey && e.key === 's')) {
                e.preventDefault();
                alert('Screen capture is restricted.');
                document.body.style.opacity = '0';
                setTimeout(() => document.body.style.opacity = '1', 2000);
            }
        });

        const SALT = "${saltB64}";
        const IV = "${ivB64}";
        const TYPE = "${fileMeta.type}";
        const NAME = "${fileMeta.name}";
        const ID = "${fileMeta.id}";
        const MODE = "${fileMeta.authMode}";
        const EXPIRY = "${fileMeta.expiryDate || ''}";

        const storagePassKey = 'sv_pass_' + ID;
        const storageViewKey = 'sv_viewed_' + ID;

        window.onload = function() {
            try {
                if (EXPIRY && Date.now() > new Date(EXPIRY).getTime()) {
                    expireFile('time');
                    return;
                }

                if (MODE === 'view-once') {
                    if (localStorage.getItem(storageViewKey)) {
                        expireFile('view-once');
                        return;
                    }
                    document.getElementById('status').innerText = "This file will lock after viewing.";
                }

                if (MODE === 'persistent') {
                    const saved = localStorage.getItem(storagePassKey);
                    if (saved) {
                        window.CACHED_PASS = saved;
                        document.getElementById('status').innerText = "Quick Access Ready. Click Unlock.";
                    } else {
                        document.getElementById('status').innerText = "Password will be saved for next time.";
                    }
                }
            } catch(e) {
                console.warn('Storage prohibited');
            }
        };

        function expireFile(reason) {
             const auth = document.getElementById('auth');
             let msg = 'This file has expired.';
             if (reason === 'time') {
                const dateStr = new Date(EXPIRY).toLocaleString();
                msg = 'File expired on ' + dateStr;
             } else if (reason === 'view-once') {
                msg = 'This file has already been viewed.';
             }
             
             auth.innerHTML = '<div class="expired-msg">File Expired</div><p style="color:#64748b">' + msg + '</p>';
        }

        function toUint8(b64) {
            const bin = atob(b64);
            const len = bin.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
        }

        async function unlock() {
            let pwd = document.getElementById('pwd').value;
            if (window.CACHED_PASS) pwd = window.CACHED_PASS;
            const btn = document.querySelector('#input-area button');
            const err = document.getElementById('error');
            const status = document.getElementById('status');
            
            if (!pwd) return;

            try {
                if(btn) btn.innerText = "Decrypting...";
                err.style.display = 'none';
                
                const salt = toUint8(SALT);
                const iv = toUint8(IV);
                const encrypted = toUint8(DATA);
                
                const enc = new TextEncoder();
                const keyMaterial = await window.crypto.subtle.importKey("raw", enc.encode(pwd), "PBKDF2", false, ["deriveKey"]);
                const key = await window.crypto.subtle.deriveKey({ name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
                
                const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, encrypted);
                
                try {
                    if (MODE === 'persistent') localStorage.setItem(storagePassKey, pwd);
                    if (MODE === 'view-once') localStorage.setItem(storageViewKey, 'true');
                } catch(e){}

                const blob = new Blob([decrypted], { type: TYPE });
                const url = URL.createObjectURL(blob);
                
                document.getElementById('auth').style.display = 'none';
                const v = document.getElementById('viewer');
                v.style.display = 'flex';
                
                // Close button
                const closeBtn = document.createElement('button');
                closeBtn.innerText = "✕ Close";
                closeBtn.className = "close-btn";
                closeBtn.onclick = () => location.reload();
                v.appendChild(closeBtn);

                if (TYPE.startsWith('video')) {
                    const vid = document.createElement('video');
                    vid.src = url;
                    vid.controls = true;
                    vid.autoplay = true;
                    v.appendChild(vid);
                } else if (TYPE.startsWith('audio')) {
                    const aud = document.createElement('audio');
                    aud.src = url;
                    aud.controls = true;
                    aud.autoplay = true;
                    v.appendChild(aud);
                } else if (TYPE.startsWith('image')) {
                    const img = document.createElement('img');
                    img.src = url;
                    v.appendChild(img);
                } else if (TYPE === 'application/pdf' || TYPE.startsWith('text/')) {
                    const iframe = document.createElement('iframe');
                    iframe.src = url;
                    iframe.style.cssText = "width:100%;height:100%;border:none;background:#fff;border-radius:8px;";
                    v.appendChild(iframe);
                } else {
                    if (MODE !== 'view-once') {
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = NAME;
                        a.innerText = "Download File";
                        a.style.cssText = "margin-top:20px;padding:14px 28px;background:#0f172a;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;display:inline-block;";
                        v.appendChild(a);
                    } else {
                         const msg = document.createElement('p');
                         msg.innerText = "Download not available in View-Once mode.";
                         msg.style.cssText = "color:#ef4444;font-weight:500;margin-top:20px;";
                         v.appendChild(msg);
                    }
                }
                
            } catch (e) {
                console.error(e);
                err.style.display = 'block';
                if(btn) btn.innerText = "Unlock File";
                if(status) status.innerText = "";
                try {
                   if (MODE === 'persistent' && localStorage.getItem(storagePassKey) === pwd) {
                        localStorage.removeItem(storagePassKey); 
                        if(status) status.innerText = "Saved password was incorrect.";
                   }
                } catch(e){}
            }
        }

        document.getElementById('pwd').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') unlock();
        });
        
        const DATA = "`;

  const footer = `";
    </script>
</body>
</html>`;

  return { header, footer };
}


// Helper to decrypt strictly for export (using internal storage keys)
async function decryptFileForExport(fileRecord, providedPassword = null) {
  // We need to unlock it first.
  let fileKey = null;
  let usedPassword = providedPassword;

  // 1. Try provided password first if available
  if (providedPassword) {
    try {
      const passKeyEntry = fileRecord.keys.find(k => k.type === 'password');
      if (passKeyEntry) {
        const passwordKey = await SecureCrypto.deriveKeyFromPassword(providedPassword, passKeyEntry.salt);
        fileKey = await SecureCrypto.unwrapKey(passKeyEntry.data, passwordKey, passKeyEntry.iv);
      }
    } catch (e) {
      console.log('Provided password invalid for unlock');
      // Fall through to other methods
    }
  }

  // 2. If no key yet, try Persistent Access (Device Key)
  if (!fileKey && fileRecord.authMode === 'persistent') {
    const devKeyEntry = fileRecord.keys.find(k => k.type === 'device');
    if (devKeyEntry) {
      try {
        const devKey = await SecureCrypto.getDeviceKey();
        fileKey = await SecureCrypto.unwrapKey(devKeyEntry.data, devKey, devKeyEntry.iv);
        // If successful, we don't have the password, so usedPassword remains null (unless provided was wrong but non-null)
        if (!providedPassword) usedPassword = null;
      } catch (e) { }
    }
  }

  // 3. If still no key, we MUST ask for the original password
  if (!fileKey) {
    const password = await showPrompt('Decrypt for Export', 'Provide the ORIGINAL password to decrypt for export:', { inputType: 'password', placeholder: 'Enter password...' });
    if (!password) return null;

    try {
      const passKeyEntry = fileRecord.keys.find(k => k.type === 'password');
      const passwordKey = await SecureCrypto.deriveKeyFromPassword(password, passKeyEntry.salt);
      fileKey = await SecureCrypto.unwrapKey(passKeyEntry.data, passwordKey, passKeyEntry.iv);
      usedPassword = password; // Capture it
    } catch (err) {
      await showAlert('Error', 'Incorrect password');
      return null;
    }
  }

  const buffer = await SecureCrypto.decryptData(fileKey, fileRecord.iv, fileRecord.content);
  return { buffer, password: usedPassword };
}



// --- Logic: Add File ---

async function handleAddFile() {
  const file = fileInput.files[0];
  const password = document.getElementById('new-password').value;
  const authMode = document.querySelector('input[name="auth-mode"]:checked').value;
  const expiryDate = document.getElementById('expiry-date')?.value || null;
  const note = document.getElementById('file-note')?.value || '';

  if (!file) {
    await showAlert('Required', 'Please select a file');
    return;
  }
  if (!password) {
    await showAlert('Required', 'Password is required');
    return;
  }

  const confirmBtn = document.getElementById('confirm-add');
  const originalText = confirmBtn.innerText;
  confirmBtn.innerText = 'Encrypting...';
  confirmBtn.disabled = true;

  try {
    // 1. Generate keys
    const fileKey = await SecureCrypto.generateKey();
    const salt = SecureCrypto.generateSalt();
    const passwordKey = await SecureCrypto.deriveKeyFromPassword(password, salt);

    // 2. Encrypt Content
    const fileBuffer = await file.arrayBuffer();
    const { iv: fileIv, ciphertext } = await SecureCrypto.encryptData(fileKey, fileBuffer);

    // 3. Wrap Keys
    // Wrap with Password
    const { iv: wrapIv, wrappedData: wrappedWithPass } = await SecureCrypto.wrapKey(fileKey, passwordKey);

    const keys = [
      { type: 'password', salt: salt, iv: wrapIv, data: wrappedWithPass }
    ];

    // If Persistent, Wrap with Device Key
    if (authMode === 'persistent') {
      const deviceKey = await SecureCrypto.getDeviceKey();
      const { iv: dWrapIv, wrappedData: wrappedWithDevice } = await SecureCrypto.wrapKey(fileKey, deviceKey);
      keys.push({ type: 'device', iv: dWrapIv, data: wrappedWithDevice });
    }

    // 4. Create Record
    const fileRecord = {
      id: crypto.randomUUID(),
      name: file.name,
      type: file.type,
      size: file.size,
      date: Date.now(),
      authMode: authMode,
      keys: keys,
      content: ciphertext,
      iv: fileIv,
      viewCount: 0,
      expiryDate: expiryDate,
      note: note,
      accessLog: [{ action: 'created', date: Date.now() }]
    };

    await DB.saveFile(fileRecord);

    addModal.close();
    resetAddForm();
    renderFileList();

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Encryption failed: ' + err.message);
  } finally {
    confirmBtn.innerText = originalText;
    confirmBtn.disabled = false;
  }
}

// --- Logic: Open File ---

async function onFileClick(fileId) {
  try {
    const fileRecord = await DB.getFile(fileId);
    if (!fileRecord) {
      await showAlert('Error', 'File not found');
      return;
    }
    selectedFileForAuth = fileRecord;

    // Check Persistent Access (Device Key)
    if (fileRecord.authMode === 'persistent') {
      const deviceKeyEntry = fileRecord.keys.find(k => k.type === 'device');
      if (deviceKeyEntry) {
        try {
          const deviceKey = await SecureCrypto.getDeviceKey();
          const fileKey = await SecureCrypto.unwrapKey(deviceKeyEntry.data, deviceKey, deviceKeyEntry.iv);
          // Success! Open Viewer
          return openViewer(fileRecord, fileKey);
        } catch (e) {
          console.log('Device unlock failed (key changed?), falling back to password');
        }
      }
    }

    // Fallback or Always/View-Once: Ask Password
    document.getElementById('auth-file-name').innerText = fileRecord.name;
    authModal.showModal();

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Error opening file');
  }
}

async function handleAuthSubmit() {
  const password = document.getElementById('auth-password').value;
  if (!selectedFileForAuth || !password) return;

  const btn = document.getElementById('confirm-auth');
  btn.innerText = 'Unlocking...';

  try {
    const fileRecord = selectedFileForAuth;
    const passKeyEntry = fileRecord.keys.find(k => k.type === 'password');
    if (!passKeyEntry) throw new Error('Corrupt key data');

    // Derive key
    const passwordKey = await SecureCrypto.deriveKeyFromPassword(password, passKeyEntry.salt);

    // Unwrap
    const fileKey = await SecureCrypto.unwrapKey(passKeyEntry.data, passwordKey, passKeyEntry.iv);

    // If mode is Persistent and missing device key (maybe first open or cleared), add it now?
    // Requirement: "Password required only on first open". 
    // If it *is* persistent mode but we are here, it likely means we didn't have the device key wrapper yet (OR logic above failed).
    // Actually, in handleAddFile, we add the device key wrapper IF persistent. 
    // So if it's there, we shouldn't be asking for password unless device key changed.

    authModal.close();
    document.getElementById('auth-password').value = '';
    openViewer(fileRecord, fileKey);

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Incorrect password or error.');
  } finally {
    btn.innerText = 'Unlock';
  }
}

// --- Logic: Viewer ---

async function openViewer(fileRecord, fileKey) {
  try {
    // Decrypt
    const decryptedBuffer = await SecureCrypto.decryptData(fileKey, fileRecord.iv, fileRecord.content);
    const blob = new Blob([decryptedBuffer], { type: fileRecord.type });
    currentDecryptedUrl = URL.createObjectURL(blob);

    // UI
    const container = document.getElementById('viewer-content');
    container.innerHTML = '';

    if (fileRecord.type.startsWith('image/')) {
      const img = document.createElement('img');
      img.src = currentDecryptedUrl;
      container.appendChild(img);
    } else if (fileRecord.type.startsWith('video/') || fileRecord.type.startsWith('audio/')) {
      const media = document.createElement(fileRecord.type.startsWith('video/') ? 'video' : 'audio');
      media.src = currentDecryptedUrl;
      media.controls = true;
      media.autoplay = true;
      // Anti-download
      media.setAttribute('controlsList', 'nodownload');
      container.appendChild(media);
    } else if (fileRecord.type === 'application/pdf') {
      const iframe = document.createElement('iframe');
      iframe.src = currentDecryptedUrl + '#toolbar=0'; // Disable toolbar
      iframe.style.width = '100%';
      iframe.style.height = '100%';
      container.appendChild(iframe);
    } else {
      container.innerText = "Preview not supported for this file type.";
    }

    document.getElementById('viewer-filename').innerText = fileRecord.name;
    viewer.classList.remove('hidden');

    // Track recently viewed
    addToRecentlyViewed(fileRecord);

    // Handle View Once
    if (fileRecord.authMode === 'view-once') {
      currentViewOnceId = fileRecord.id;
      document.getElementById('viewer-timer').classList.remove('hidden');
      localStorage.setItem('sv_crash_guard', fileRecord.id); // Mark for deletion on crash

      // Update view count?
      fileRecord.viewCount = (fileRecord.viewCount || 0) + 1;
      await DB.updateFile(fileRecord);
    } else {
      document.getElementById('viewer-timer').classList.add('hidden');
      currentViewOnceId = null;
    }

  } catch (err) {
    console.error(err);
    await showAlert('Error', 'Decryption failed.');
  }
}

async function closeViewer() {
  viewer.classList.add('hidden');
  document.getElementById('viewer-content').innerHTML = ''; // Clear memory hints

  if (currentDecryptedUrl) {
    URL.revokeObjectURL(currentDecryptedUrl);
    currentDecryptedUrl = null;
  }

  // Handle Logic: If View Once, Delete Now
  if (currentViewOnceId) {
    await DB.deleteFile(currentViewOnceId);
    localStorage.removeItem('sv_crash_guard');
    currentViewOnceId = null;
    renderFileList();
    await showAlert('Security', 'File self-destructed as per security policy.');
  }
}

// --- Logic: Security ---

async function checkCrashRecovery() {
  // If we have a crash guard ID, it means the app closed while viewing a view-once file.
  const crashId = localStorage.getItem('sv_crash_guard');
  if (crashId) {
    console.log('Detected unclean shutdown during self-destruct viewing. Cleaning up...');
    await DB.deleteFile(crashId);
    localStorage.removeItem('sv_crash_guard');
    await showAlert('Security Notice', 'A self-destruct file was detected during an unclean shutdown and has been securely removed.');
    renderFileList();
  }
}

// Privacy Curtain functions removed as feature was requested to be deleted.


// --- Rendering ---

async function renderFileList(searchQuery = '') {
  fileList.innerHTML = '';
  let files = await DB.getAllFiles();
  allFiles = files; // Cache for other functions

  // Update storage usage
  updateStorageUsage(files);

  // Filter by search
  if (searchQuery) {
    files = files.filter(f => f.name.toLowerCase().includes(searchQuery.toLowerCase()));
  }

  // Sort
  const sortValue = sortSelect?.value || 'date-desc';
  files.sort((a, b) => {
    // Favorites first
    if (a.favorite && !b.favorite) return -1;
    if (!a.favorite && b.favorite) return 1;

    switch (sortValue) {
      case 'date-desc': return (b.date || 0) - (a.date || 0);
      case 'date-asc': return (a.date || 0) - (b.date || 0);
      case 'name-asc': return a.name.localeCompare(b.name);
      case 'name-desc': return b.name.localeCompare(a.name);
      case 'size-desc': return (b.size || 0) - (a.size || 0);
      case 'size-asc': return (a.size || 0) - (b.size || 0);
      default: return 0;
    }
  });

  // Show/hide quick tips based on file count
  const quickTips = document.getElementById('quick-tips');
  if (quickTips) {
    if (allFiles.length === 0) {
      quickTips.classList.remove('hidden');
    } else {
      quickTips.classList.add('hidden');
    }
  }

  if (files.length === 0) {
    fileList.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔐</div>
        <p>${searchQuery ? 'No files match your search.' : 'No secured files yet.'}</p>
        <small>${searchQuery ? 'Try a different search term.' : 'Tap + to secure your first file'}</small>
      </div>`;
    return;
  }

  files.forEach((file, index) => {
    const el = document.createElement('div');
    el.className = 'file-card';
    el.style.animationDelay = `${index * 0.05}s`;

    // Check if expired
    const isExpired = file.expiryDate && new Date(file.expiryDate).getTime() < Date.now();

    // Click handler
    el.onclick = async (e) => {
      if (!e.target.closest('.file-actions') && !e.target.closest('.select-checkbox') && !e.target.closest('.favorite-btn')) {
        if (isExpired) {
          await showAlert('Expired', 'This file has expired and will be deleted.');
          DB.deleteFile(file.id).then(() => renderFileList());
          return;
        }
        onFileClick(file.id);
      }
    };

    let icon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>';
    if (file.type?.startsWith('image')) icon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>';
    if (file.type?.startsWith('video')) icon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"></polygon><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>';
    if (file.type?.startsWith('audio')) icon = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18V5l12-2v13"></path><circle cx="6" cy="18" r="3"></circle><circle cx="18" cy="16" r="3"></circle></svg>';

    let badges = '';
    if (file.authMode === 'view-once') badges += `<span class="badge view-once">View Once</span>`;
    if (file.authMode === 'persistent') badges += `<span class="badge persistent">Persistent</span>`;
    if (file.expiryDate) badges += `<span class="badge ${isExpired ? 'view-once' : ''}">${isExpired ? 'Expired' : 'Expires ' + new Date(file.expiryDate).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })}</span>`;
    if (file.note) badges += `<span class="badge" title="${file.note}">📝</span>`;

    const isSelected = selectedFiles.has(file.id);
    const isFavorite = file.favorite;

    let displayName = file.name;
    // Feature "Show Extensions" removed, displaying full name by default.
    // if (!showExtensions && displayName.includes('.')) {
    //   displayName = displayName.substring(0, displayName.lastIndexOf('.'));
    // }

    el.innerHTML = `
        ${isExpired ? '<div class="expired-overlay">⏰ EXPIRED</div>' : ''}
        <input type="checkbox" class="select-checkbox" ${isSelected ? 'checked' : ''} />
        
        <div class="file-left-col">
           <div class="file-icon">${icon}</div>
           <div class="file-primary-actions">
               <button class="btn-highlight share-btn">Share</button>
               <button class="btn-highlight custom-share-btn">Custom</button>
           </div>
        </div>

        <div class="file-info">
            <h3>${displayName}</h3>
            <div class="file-meta">
                <span>${(file.size / 1024 / 1024).toFixed(2)} MB</span>
                ${badges}
            </div>
            <div class="file-actions">
                <button class="btn-small info-btn">Info</button>
                <button class="btn-small rename-btn">Rename</button>
                <button class="btn-small change-pass-btn">Change Password</button>
                <button class="btn-small delete-btn">Delete</button>
            </div>
        </div>
    `;

    // Event listeners
    el.querySelector('.select-checkbox').onchange = (e) => {
      e.stopPropagation();
      if (e.target.checked) {
        selectedFiles.add(file.id);
      } else {
        selectedFiles.delete(file.id);
      }
      updateBulkUI();
    };

    el.querySelector('.info-btn').onclick = (e) => showFileInfo(e, file.id);
    el.querySelector('.rename-btn').onclick = (e) => openRenameModal(e, file.id, file.name);
    el.querySelector('.change-pass-btn').onclick = (e) => openChangePasswordModal(e, file.id, file.name);
    el.querySelector('.share-btn').onclick = (e) => handleShareFile(e, file.id);
    el.querySelector('.custom-share-btn').onclick = (e) => handleCustomShare(e, file.id);
    el.querySelector('.delete-btn').onclick = (e) => handleDeleteFile(e, file.id);

    fileList.appendChild(el);
  });
}

// --- Settings Features ---

function loadSettings() {
  // Privacy & Extension Toggles Removed
  // New Features Removed

  // Remove lock button visibility
  const removeBtn = document.getElementById('remove-app-lock');
  if (removeBtn) removeBtn.style.display = appLockPassword ? 'block' : 'none';

  // Load Panic Setting
  const savedAction = localStorage.getItem('sv_panic_action') || 'lock';
  const panicSelect = document.getElementById('panic-action-select');
  if (panicSelect) panicSelect.value = savedAction;

  // Load Panic Enabled Toggle
  const panicEnabled = localStorage.getItem('sv_panic_enabled') === 'true'; // Default false
  const panicToggle = document.getElementById('panic-enable-toggle');
  if (panicToggle) panicToggle.checked = panicEnabled;
  updatePanicVisibility();
}

async function handleSetAppLock() {
  const pass = document.getElementById('app-lock-password').value;
  if (!pass) {
    await showAlert('Required', 'Please enter a password');
    return;
  }

  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pass));
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');

  localStorage.setItem('sv_app_lock', hashHex);
  appLockPassword = hashHex;
  await showAlert('Success', 'App Lock Password Set!');
  document.getElementById('app-lock-password').value = '';
  loadSettings();
}

async function handleRemoveAppLock() {
  const confirmed = await showConfirm('Remove App Lock', 'Remove App Lock password?');
  if (confirmed) {
    localStorage.removeItem('sv_app_lock');
    appLockPassword = null;
    await showAlert('Success', 'App Lock removed.');
    loadSettings();
  }
}

async function checkAppLock() {
  if (!appLockPassword) return;

  const overlay = document.getElementById('app-lock-screen');
  const input = document.getElementById('lock-input');
  const btn = document.getElementById('unlock-submit');

  overlay.classList.remove('hidden');

  const attemptUnlock = async () => {
    const pass = input.value;
    if (!pass) return;

    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pass));
    const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');

    if (hashHex === appLockPassword) {
      overlay.classList.add('hidden');
      input.value = '';
    } else {
      await showAlert('Error', 'Incorrect Password');
      input.value = '';
      input.focus();
    }
  };

  btn.onclick = attemptUnlock;
  input.onkeydown = (e) => {
    if (e.key === 'Enter') attemptUnlock();
  };
}

// --- Panic Button Feature ---
function updatePanicVisibility() {
  const isEnabled = localStorage.getItem('sv_panic_enabled') === 'true';
  const headerBtn = document.getElementById('header-panic-wrapper');
  const settingsContent = document.getElementById('panic-settings-content');

  // Show/Hide Header Button
  if (headerBtn) {
    if (isEnabled) {
      headerBtn.classList.remove('hidden');
      headerBtn.style.display = 'flex'; // Ensure flex display if using classList doesn't fully override
    } else {
      headerBtn.classList.add('hidden');
      headerBtn.style.display = 'none';
    }
  }

  // Show/Hide Settings Content
  if (settingsContent) {
    if (isEnabled) {
      settingsContent.classList.remove('hidden');
      settingsContent.style.opacity = '1';
      settingsContent.style.pointerEvents = 'auto';
    } else {
      settingsContent.classList.add('hidden');
      settingsContent.style.opacity = '0.5';
      settingsContent.style.pointerEvents = 'none';
    }
  }
}

function triggerPanic() {
  const action = localStorage.getItem('sv_panic_action') || 'lock'; // Default is now lock

  if (action === 'none') {
    return;
  } else if (action === 'erase') {
    // Immediate wipe without confirmation - but preserve panic setting
    (async () => {
      try {
        const panicSetting = localStorage.getItem('sv_panic_action'); // Preserve
        const files = await DB.getAllFiles();
        for (const file of files) await DB.deleteFile(file.id);
        localStorage.clear();
        if (panicSetting) localStorage.setItem('sv_panic_action', panicSetting); // Restore
        location.reload();
      } catch (e) { console.error(e); }
    })();
  } else if (action === 'lock') {
    // Check if app lock is set
    if (!appLockPassword) {
      showAlert('App Lock Not Set', 'Please set an App Lock password in Settings first to use this feature.');
      return;
    }
    // Reload triggers app lock on init if set
    window.location.reload();
  } else if (action === 'blur') {
    const overlay = document.createElement('div');
    overlay.className = 'panic-overlay blur-mode';
    overlay.innerHTML = `
           <div class="panic-message">System Error (0xCRITICAL)</div>
           <div class="panic-message" style="font-size:16px;font-weight:400;margin-bottom:24px;">Please reload the application.</div>
           <div class="reload-icon-btn" id="panic-reload-btn">
              <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                 <polyline points="23 4 23 10 17 10"></polyline>
                 <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
              </svg>
           </div>
           <div class="pull-to-reload">↓ Pull down or tap icon to reload</div> 
      `;
    document.body.appendChild(overlay);

    // Click icon to reload
    document.getElementById('panic-reload-btn')?.addEventListener('click', () => {
      window.location.reload();
    });
  } else if (action === 'loading') {
    const overlay = document.createElement('div');
    overlay.className = 'panic-overlay';
    overlay.innerHTML = `<div class="fake-loading-spinner"></div><div style="color:var(--gray-500)">Loading resources...</div>
      <div style="margin-top:20px; font-size:12px; opacity:0.5">(Touch to enter)</div>`;
    document.body.appendChild(overlay);

    const remove = () => overlay.remove();
    overlay.addEventListener('click', remove);
    overlay.addEventListener('touchstart', remove);
  }
}


