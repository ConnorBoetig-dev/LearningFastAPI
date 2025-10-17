// =============================================================================================
// APP.JS - FRONTEND AUTHENTICATION & FILE UPLOAD LOGIC
// =============================================================================================
// This file handles:
// - User login (POST /auth/login)
// - Token management (access + refresh tokens stored in memory)
// - Automatic token refresh on 401 errors
// - File upload with progress tracking (XMLHttpRequest for progress events)
// - User profile fetching
// - Logout
//
// SECURITY NOTES:
// - Tokens stored in memory (variables), NOT localStorage (safer against XSS)
// - Tokens lost on page refresh (user must log in again)
// - No CORS needed (frontend served from same origin as API)
// =============================================================================================

// -------------------------
// GLOBAL STATE (tokens stored in memory)
// -------------------------
let accessToken = null;     // Short-lived token (15 minutes) for API requests
let refreshToken = null;    // Long-lived token (30 days) for getting new access tokens
let currentUser = null;     // User profile data (email, id, created_at)

// -------------------------
// DOM ELEMENTS (cached for performance)
// -------------------------
const loginSection = document.getElementById('login-section');
const profileSection = document.getElementById('profile-section');
const uploadSection = document.getElementById('upload-section');
const statusSection = document.getElementById('status-section');
const resultsSection = document.getElementById('results-section');

const loginForm = document.getElementById('login-form');
const uploadForm = document.getElementById('upload-form');
const logoutBtn = document.getElementById('logout-btn');

const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const fileInput = document.getElementById('file-input');

const userInfoDiv = document.getElementById('user-info');
const statusContent = document.getElementById('status-content');
const resultsContent = document.getElementById('results-content');

const uploadProgress = document.getElementById('upload-progress');
const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');

// -------------------------
// INITIALIZATION (run when page loads)
// -------------------------
document.addEventListener('DOMContentLoaded', () => {
    // Attach event listeners
    loginForm.addEventListener('submit', handleLogin);
    uploadForm.addEventListener('submit', handleUpload);
    logoutBtn.addEventListener('click', handleLogout);

    showStatus('Ready. Please log in to upload files.', 'info');
});

// =============================================================================================
// AUTHENTICATION FUNCTIONS
// =============================================================================================

/**
 * Handle login form submission
 *
 * FLOW:
 * 1. Prevent form default submit (no page reload)
 * 2. Get email and password from inputs
 * 3. Call login() function
 * 4. On success, fetch user profile and show upload UI
 * 5. On error, show error message
 */
async function handleLogin(event) {
    event.preventDefault();

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
        showStatus('Please enter both email and password', 'error');
        return;
    }

    showStatus('Logging in...', 'info');

    try {
        await login(email, password);
        showStatus('Login successful!', 'success');

        // Fetch user profile
        await fetchUserProfile();

        // Show upload UI, hide login UI
        loginSection.classList.add('hidden');
        profileSection.classList.remove('hidden');
        uploadSection.classList.remove('hidden');

        // Clear password field for security
        passwordInput.value = '';

    } catch (error) {
        showStatus(`Login failed: ${error.message}`, 'error');
    }
}

/**
 * Login function - calls POST /auth/login
 *
 * WHAT IT DOES:
 * - Sends email/password to /auth/login endpoint
 * - Receives access token (15 min expiry) and refresh token (30 day expiry)
 * - Stores both tokens in memory (variables)
 *
 * SECURITY:
 * - Tokens stored in JavaScript variables (memory only)
 * - NOT stored in localStorage (vulnerable to XSS)
 * - Tokens lost on page refresh (acceptable trade-off for security)
 *
 * @param {string} email - User's email address
 * @param {string} password - User's password (sent over HTTPS)
 * @returns {Promise<void>}
 * @throws {Error} If login fails (wrong credentials, network error, etc.)
 */
async function login(email, password) {
    const response = await fetch('/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
        credentials: 'omit',  // Don't send cookies (we use Bearer tokens)
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();

    // Store tokens in memory
    accessToken = data.access_token;
    refreshToken = data.refresh_token;

    console.log('Login successful. Tokens stored in memory.');
}

/**
 * Refresh access token using refresh token
 *
 * TOKEN ROTATION FLOW:
 * 1. Send refresh token to /auth/refresh
 * 2. Server validates refresh token (checks DB for revocation/expiration)
 * 3. Server issues NEW access token + NEW refresh token
 * 4. Server marks OLD refresh token as revoked (one-time use)
 * 5. Update tokens in memory
 *
 * WHY ROTATION?
 * - If refresh token is stolen, attacker can only use it once
 * - Legitimate user gets new token, stolen token is revoked
 * - Limits damage from token theft
 *
 * @returns {Promise<void>}
 * @throws {Error} If refresh fails (revoked token, expired, network error)
 */
async function refresh() {
    console.log('Access token expired. Refreshing...');

    if (!refreshToken) {
        throw new Error('No refresh token available. Please log in again.');
    }

    const response = await fetch('/auth/refresh', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
        credentials: 'omit',
    });

    if (!response.ok) {
        // Refresh failed - tokens are invalid/revoked
        // Clear tokens and force re-login
        accessToken = null;
        refreshToken = null;
        currentUser = null;
        throw new Error('Session expired. Please log in again.');
    }

    const data = await response.json();

    // Update tokens with new values
    accessToken = data.access_token;
    refreshToken = data.refresh_token;

    console.log('Tokens refreshed successfully.');
}

/**
 * Authenticated fetch wrapper with automatic token refresh
 *
 * WHAT IT DOES:
 * 1. Adds Authorization header with access token
 * 2. Makes the request
 * 3. If 401 Unauthorized → automatically refresh token and retry once
 * 4. If refresh fails → throw error (user must log in again)
 *
 * USAGE:
 *   const response = await authFetch('/auth/me');
 *   const user = await response.json();
 *
 * WHY AUTO-REFRESH?
 * - Access tokens expire after 15 minutes
 * - User shouldn't have to manually click "refresh" button
 * - Transparent token rotation improves UX
 *
 * @param {string} url - API endpoint to call
 * @param {object} options - Fetch options (method, headers, body, etc.)
 * @returns {Promise<Response>} Fetch response object
 * @throws {Error} If both initial request and retry fail, or if no access token
 */
async function authFetch(url, options = {}) {
    if (!accessToken) {
        throw new Error('Not authenticated. Please log in.');
    }

    // Add Authorization header with access token
    options.headers = {
        ...options.headers,
        'Authorization': `Bearer ${accessToken}`,
    };

    options.credentials = 'omit';

    // Make the request
    let response = await fetch(url, options);

    // If 401 Unauthorized, try refreshing token
    if (response.status === 401) {
        console.log('Received 401. Attempting token refresh...');

        try {
            // Refresh tokens
            await refresh();

            // Retry original request with new access token
            options.headers['Authorization'] = `Bearer ${accessToken}`;
            response = await fetch(url, options);

            console.log('Retry successful after token refresh.');

        } catch (error) {
            // Refresh failed - redirect to login
            showStatus('Session expired. Please log in again.', 'error');
            handleLogout();
            throw error;
        }
    }

    return response;
}

/**
 * Fetch current user profile
 *
 * Calls GET /auth/me to get user info (email, id, created_at)
 * Uses authFetch for automatic token refresh if needed
 */
async function fetchUserProfile() {
    try {
        const response = await authFetch('/auth/me');

        if (!response.ok) {
            throw new Error('Failed to fetch user profile');
        }

        currentUser = await response.json();

        // Display user info
        userInfoDiv.innerHTML = `
            <p><strong>Email:</strong> ${currentUser.email}</p>
            <p><strong>User ID:</strong> ${currentUser.id}</p>
            <p><strong>Member since:</strong> ${new Date(currentUser.created_at).toLocaleDateString()}</p>
        `;

    } catch (error) {
        showStatus(`Failed to load profile: ${error.message}`, 'error');
    }
}

/**
 * Handle logout
 *
 * FLOW:
 * 1. Call POST /auth/logout with refresh token
 * 2. Server marks refresh token as revoked in database
 * 3. Clear tokens from memory
 * 4. Reset UI to login screen
 *
 * NOTE: Even if logout request fails, we clear tokens locally
 */
async function handleLogout() {
    // Try to revoke refresh token on server
    if (refreshToken) {
        try {
            await fetch('/auth/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refresh_token: refreshToken }),
                credentials: 'omit',
            });
        } catch (error) {
            console.error('Logout request failed:', error);
            // Continue with local logout even if server request fails
        }
    }

    // Clear tokens and user data
    accessToken = null;
    refreshToken = null;
    currentUser = null;

    // Reset UI
    loginSection.classList.remove('hidden');
    profileSection.classList.add('hidden');
    uploadSection.classList.add('hidden');
    resultsSection.classList.add('hidden');

    // Clear forms
    emailInput.value = '';
    passwordInput.value = '';
    fileInput.value = '';

    showStatus('Logged out successfully.', 'info');
}

// =============================================================================================
// FILE UPLOAD FUNCTIONS
// =============================================================================================

/**
 * Handle upload form submission
 *
 * FLOW:
 * 1. Prevent form default submit
 * 2. Get selected file
 * 3. Call uploadFile() with progress tracking
 * 4. Display results
 */
async function handleUpload(event) {
    event.preventDefault();

    const file = fileInput.files[0];

    if (!file) {
        showStatus('Please select a file to upload', 'error');
        return;
    }

    showStatus(`Uploading ${file.name} (${formatFileSize(file.size)})...`, 'info');

    try {
        const result = await uploadFile(file);

        // Show success message
        showStatus('Upload successful!', 'success');

        // Display upload result
        resultsSection.classList.remove('hidden');
        resultsContent.textContent = JSON.stringify(result, null, 2);

        // Clear file input
        fileInput.value = '';

    } catch (error) {
        showStatus(`Upload failed: ${error.message}`, 'error');
    }
}

/**
 * Upload file with progress tracking
 *
 * WHY XMLHttpRequest INSTEAD OF FETCH?
 * - fetch() doesn't support upload progress events
 * - XMLHttpRequest has 'upload.onprogress' event for tracking
 * - Can show progress bar to user
 *
 * FLOW:
 * 1. Create FormData with file
 * 2. Create XMLHttpRequest
 * 3. Set Authorization header with access token
 * 4. Track upload progress (update progress bar)
 * 5. Handle response (success or error)
 * 6. On 401, refresh token and retry
 *
 * @param {File} file - File object from input element
 * @returns {Promise<object>} Upload result with filename, key, url, status
 * @throws {Error} If upload fails or authentication fails
 */
function uploadFile(file) {
    return new Promise((resolve, reject) => {
        if (!accessToken) {
            reject(new Error('Not authenticated. Please log in.'));
            return;
        }

        // Create FormData with file
        const formData = new FormData();
        formData.append('file', file);

        // Create XMLHttpRequest (for progress tracking)
        const xhr = new XMLHttpRequest();

        // Track upload progress
        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const percentComplete = Math.round((event.loaded / event.total) * 100);
                updateProgress(percentComplete);
            }
        });

        // Handle upload completion
        xhr.addEventListener('load', async () => {
            hideProgress();

            if (xhr.status === 200) {
                // Success
                const result = JSON.parse(xhr.responseText);
                resolve(result);

            } else if (xhr.status === 401) {
                // Access token expired - try to refresh and retry
                console.log('Upload received 401. Attempting token refresh...');

                try {
                    await refresh();

                    // Retry upload with new access token
                    showStatus('Token refreshed. Retrying upload...', 'info');
                    const retryResult = await uploadFile(file);
                    resolve(retryResult);

                } catch (error) {
                    reject(new Error('Session expired. Please log in again.'));
                    handleLogout();
                }

            } else {
                // Other error
                let errorMessage = 'Upload failed';
                try {
                    const errorData = JSON.parse(xhr.responseText);
                    errorMessage = errorData.detail || errorMessage;
                } catch (e) {
                    errorMessage = xhr.statusText || errorMessage;
                }
                reject(new Error(errorMessage));
            }
        });

        // Handle network errors
        xhr.addEventListener('error', () => {
            hideProgress();
            reject(new Error('Network error during upload'));
        });

        // Handle upload cancellation
        xhr.addEventListener('abort', () => {
            hideProgress();
            reject(new Error('Upload cancelled'));
        });

        // Send request
        xhr.open('POST', '/upload');
        xhr.setRequestHeader('Authorization', `Bearer ${accessToken}`);
        xhr.send(formData);

        // Show progress UI
        showProgress();
    });
}

// =============================================================================================
// UI HELPER FUNCTIONS
// =============================================================================================

/**
 * Show status message
 *
 * @param {string} message - Message to display
 * @param {string} type - Message type: 'info', 'success', 'error'
 */
function showStatus(message, type = 'info') {
    const icons = {
        info: 'ℹ️',
        success: '✅',
        error: '❌',
    };

    const colors = {
        info: '#2196F3',
        success: '#4CAF50',
        error: '#f44336',
    };

    statusContent.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <span style="font-size: 24px;">${icons[type]}</span>
            <div>
                <p style="margin: 0; color: ${colors[type]}; font-weight: bold;">${message}</p>
                <p style="margin: 5px 0 0 0; color: #666; font-size: 0.9em;">${new Date().toLocaleTimeString()}</p>
            </div>
        </div>
    `;
}

/**
 * Show upload progress bar
 */
function showProgress() {
    uploadProgress.classList.remove('hidden');
    updateProgress(0);
}

/**
 * Hide upload progress bar
 */
function hideProgress() {
    uploadProgress.classList.add('hidden');
}

/**
 * Update progress bar
 *
 * @param {number} percent - Upload progress percentage (0-100)
 */
function updateProgress(percent) {
    progressFill.style.width = `${percent}%`;
    progressText.textContent = `Uploading: ${percent}%`;
}

/**
 * Format file size for display
 *
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size (e.g., "1.5 MB")
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}
