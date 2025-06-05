// JavaScript for logout functionality
// This script handles clearing sensitive data from browser storage on logout

function clearBrowserStorage() {
  try {
    // Clear keyfile from localStorage
    localStorage.removeItem('fourohfour_keyfile');
    console.log('Keyfile cleared from localStorage on logout');    // Clear master key from sessionStorage (using consistent key format)
    sessionStorage.removeItem('fourohfour_master_key');
    console.log('Cleared fourohfour_master_key from sessionStorage');

    // Also clear any legacy master keys (for backward compatibility)
    const sessionKeys = Object.keys(sessionStorage);
    sessionKeys.forEach((key) => {
      if (key.startsWith('masterKey_')) {
        sessionStorage.removeItem(key);
        console.log(`Cleared legacy master key: ${key}`);
      }
    });

    // Clear any file keys from localStorage
    const localKeys = Object.keys(localStorage);
    localKeys.forEach((key) => {
      if (key.startsWith('filekey_')) {
        localStorage.removeItem(key);
        console.log(`Cleared file key: ${key}`);
      }
    });

    console.log('Browser storage cleaned on logout');
  } catch (error) {
    console.error('Error clearing browser storage:', error);
  }
}

// Handle logout form submission
document.addEventListener('DOMContentLoaded', function () {
  const logoutForm = document.querySelector('.logout-form');

  if (logoutForm) {
    logoutForm.addEventListener('submit', function (e) {
      // Clear browser storage before submitting logout
      clearBrowserStorage();

      console.log('Logout initiated - browser storage cleared');
      // Continue with normal form submission to server
    });
  }
});

// Also provide a global function for manual logout cleanup
window.fourohfourLogout = clearBrowserStorage;
