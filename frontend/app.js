/**
 * SafeNotes Frontend Application
 *
 * Security considerations:
 * - No inline event handlers (CSP compliant)
 * - Input sanitization before display
 * - No eval() or innerHTML with user data
 * - HTTPS-only API calls in production
 */

(function () {
    'use strict';

    // API base URL - configure for your environment
    const API_BASE = window.location.hostname === 'localhost'
        ? 'http://localhost:8000'
        : '';

    // DOM Elements
    const elements = {
        // Sections
        createSection: document.getElementById('create-section'),
        successSection: document.getElementById('success-section'),
        accessSection: document.getElementById('access-section'),
        errorSection: document.getElementById('error-section'),

        // Create form
        createForm: document.getElementById('create-form'),
        contentInput: document.getElementById('content'),
        passwordInput: document.getElementById('password'),
        expirationSelect: document.getElementById('expiration'),
        createBtn: document.getElementById('create-btn'),
        charCount: document.getElementById('char-count'),

        // Success section
        noteLink: document.getElementById('note-link'),
        copyBtn: document.getElementById('copy-btn'),
        expiresAt: document.getElementById('expires-at'),
        isProtected: document.getElementById('is-protected'),
        isBurn: document.getElementById('is-burn'),
        newNoteBtn: document.getElementById('new-note-btn'),

        // Access section
        passwordForm: document.getElementById('password-form'),
        accessPassword: document.getElementById('access-password'),
        passwordError: document.getElementById('password-error'),
        noteContent: document.getElementById('note-content'),
        noteText: document.getElementById('note-text'),
        createdAt: document.getElementById('created-at'),
        burnWarning: document.getElementById('burn-warning'),
        backHomeBtn: document.getElementById('back-home-btn'),

        // Error section
        errorMessage: document.getElementById('error-message'),
        errorHomeBtn: document.getElementById('error-home-btn'),
    };

    // Current token being accessed
    let currentToken = null;

    /**
     * Initialize the application
     */
    function init() {
        // Check if we're accessing a note via URL hash
        const path = window.location.pathname;
        const match = path.match(/^\/note\/([a-zA-Z0-9_-]+)$/);

        if (match) {
            currentToken = match[1];
            showSection('access');
            accessNote(currentToken);
        } else if (window.location.hash.startsWith('#/note/')) {
            currentToken = window.location.hash.replace('#/note/', '');
            showSection('access');
            accessNote(currentToken);
        } else {
            showSection('create');
        }

        // Bind event listeners
        bindEvents();
    }

    /**
     * Bind all event listeners
     */
    function bindEvents() {
        // Character counter
        elements.contentInput.addEventListener('input', updateCharCount);

        // Create form submission
        elements.createForm.addEventListener('submit', handleCreateSubmit);

        // Copy button
        elements.copyBtn.addEventListener('click', copyLink);

        // New note button
        elements.newNoteBtn.addEventListener('click', resetToCreate);

        // Password form submission
        elements.passwordForm.addEventListener('submit', handlePasswordSubmit);

        // Back to home buttons
        elements.backHomeBtn.addEventListener('click', resetToCreate);
        elements.errorHomeBtn.addEventListener('click', resetToCreate);
    }

    /**
     * Show a specific section, hide others
     */
    function showSection(section) {
        elements.createSection.classList.add('hidden');
        elements.successSection.classList.add('hidden');
        elements.accessSection.classList.add('hidden');
        elements.errorSection.classList.add('hidden');

        switch (section) {
            case 'create':
                elements.createSection.classList.remove('hidden');
                break;
            case 'success':
                elements.successSection.classList.remove('hidden');
                break;
            case 'access':
                elements.accessSection.classList.remove('hidden');
                break;
            case 'error':
                elements.errorSection.classList.remove('hidden');
                break;
        }
    }

    /**
     * Update character counter
     */
    function updateCharCount() {
        const count = elements.contentInput.value.length;
        elements.charCount.textContent = count.toLocaleString();
    }

    /**
     * Handle create form submission
     */
    async function handleCreateSubmit(event) {
        event.preventDefault();

        const content = elements.contentInput.value.trim();
        const password = elements.passwordInput.value || null;
        const expiration = elements.expirationSelect.value;

        // Validate
        if (!content) {
            showError('Please enter a note.');
            return;
        }

        if (password && password.length < 8) {
            showError('Password must be at least 8 characters.');
            return;
        }

        // Disable button and show loading
        elements.createBtn.disabled = true;
        elements.createBtn.classList.add('loading');
        elements.createBtn.textContent = 'Creating...';

        try {
            const response = await fetch(`${API_BASE}/api/notes`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    content: content,
                    password: password,
                    expiration: expiration,
                }),
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || 'Failed to create note');
            }

            const data = await response.json();
            showSuccess(data);
        } catch (error) {
            showError(error.message || 'An error occurred. Please try again.');
        } finally {
            elements.createBtn.disabled = false;
            elements.createBtn.classList.remove('loading');
            elements.createBtn.textContent = 'Create Secure Note';
        }
    }

    /**
     * Show success section with note details
     */
    function showSuccess(data) {
        // Generate the note URL
        const noteUrl = `${window.location.origin}/note/${data.token}`;
        elements.noteLink.value = noteUrl;

        // Format expiration date
        const expiresDate = new Date(data.expires_at);
        elements.expiresAt.textContent = expiresDate.toLocaleString();

        // Set protection status
        elements.isProtected.textContent = data.password_protected ? 'Yes' : 'No';
        elements.isBurn.textContent = data.burn_after_read ? 'Yes' : 'No';

        // Clear the form
        elements.createForm.reset();
        updateCharCount();

        // Show success section
        showSection('success');
    }

    /**
     * Copy link to clipboard
     */
    async function copyLink() {
        try {
            await navigator.clipboard.writeText(elements.noteLink.value);
            elements.copyBtn.textContent = 'Copied!';
            elements.copyBtn.classList.add('copied');

            setTimeout(() => {
                elements.copyBtn.textContent = 'Copy';
                elements.copyBtn.classList.remove('copied');
            }, 2000);
        } catch (error) {
            // Fallback for older browsers
            elements.noteLink.select();
            document.execCommand('copy');
            elements.copyBtn.textContent = 'Copied!';
            setTimeout(() => {
                elements.copyBtn.textContent = 'Copy';
            }, 2000);
        }
    }

    /**
     * Reset to create section
     */
    function resetToCreate() {
        currentToken = null;
        elements.passwordForm.classList.add('hidden');
        elements.noteContent.classList.add('hidden');
        window.history.pushState({}, '', '/');
        showSection('create');
    }

    /**
     * Access a note by token
     */
    async function accessNote(token, password = null) {
        try {
            let url = `${API_BASE}/api/notes/${encodeURIComponent(token)}`;
            if (password) {
                url += `?password=${encodeURIComponent(password)}`;
            }

            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            if (response.status === 403) {
                const errorData = await response.json().catch(() => ({}));
                if (errorData.detail === 'Password required') {
                    // Show password form
                    elements.passwordForm.classList.remove('hidden');
                    elements.noteContent.classList.add('hidden');
                    elements.passwordError.classList.add('hidden');
                    return;
                } else if (errorData.detail === 'Invalid password') {
                    // Show error on password form
                    elements.passwordError.classList.remove('hidden');
                    elements.accessPassword.value = '';
                    elements.accessPassword.focus();
                    return;
                }
            }

            if (response.status === 404) {
                showError('This note does not exist or has expired.');
                return;
            }

            if (response.status === 429) {
                showError('Too many attempts. Please wait a moment and try again.');
                return;
            }

            if (!response.ok) {
                throw new Error('Failed to access note');
            }

            const data = await response.json();
            showNoteContent(data);
        } catch (error) {
            showError(error.message || 'An error occurred. Please try again.');
        }
    }

    /**
     * Handle password form submission
     */
    function handlePasswordSubmit(event) {
        event.preventDefault();
        const password = elements.accessPassword.value;

        if (!password) {
            return;
        }

        accessNote(currentToken, password);
    }

    /**
     * Show note content
     */
    function showNoteContent(data) {
        // Safely display content (textContent prevents XSS)
        elements.noteText.textContent = data.content;

        // Format created date
        const createdDate = new Date(data.created_at);
        elements.createdAt.textContent = createdDate.toLocaleString();

        // Show burn warning if applicable
        if (data.will_be_deleted) {
            elements.burnWarning.classList.remove('hidden');
        } else {
            elements.burnWarning.classList.add('hidden');
        }

        // Hide password form, show content
        elements.passwordForm.classList.add('hidden');
        elements.noteContent.classList.remove('hidden');
    }

    /**
     * Show error message
     */
    function showError(message) {
        elements.errorMessage.textContent = message;
        showSection('error');
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
