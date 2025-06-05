// JavaScript for verifyuser.html
function updateHashOutput() {
    const friendUsername = document.getElementById('friend-username-input');
    const output = document.getElementById('hash-output');
    const verifyBtn = document.getElementById('verify-new-user-btn');
    if (output.value !== "No friend username entered..." && output.value !== "Ready to generate hash") {
        verifyBtn.disabled = false;
        verifyBtn.style.display = 'inline-block';
        return;
    }
    if (!friendUsername.value) {
        output.value = "No friend username entered...";
        verifyBtn.disabled = true;
        verifyBtn.style.display = 'none';
    } else {
        output.value = "Ready to generate hash";
        verifyBtn.disabled = true;
        verifyBtn.style.display = 'none';
    }
}

// Call this after hash is generated and set in output.value
function onHashGenerated() {
    const verifyBtn = document.getElementById('verify-new-user-btn');
    verifyBtn.disabled = false;
    verifyBtn.style.display = 'inline-block';
}

function verifyNewUser() {
    const friendUsernameInput = document.getElementById('friend-username-input');
    const output = document.getElementById('hash-output');
    const verifyBtn = document.getElementById('verify-new-user-btn');
    if (!friendUsernameInput.value) {
        alert('Please enter a friend\'s username.');
        return;
    }
    if (!output.value || output.value === "No friend username entered..." || output.value === "Ready to generate hash") {
        alert('Please generate a hash for your friend first.');
        return;
    }
    // This replicates the original integrated AJAX logic from the template
    fetch('/verify_new_user', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        body: JSON.stringify({
            friend_username: friendUsernameInput.value,
            hash: output.value
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('User verified successfully!');
            // Optionally, redirect or update UI
        } else {
            alert('Verification failed: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        alert('An error occurred: ' + error);
    });
}

// Remove the setTimeout/onHashGenerated logic and instead update the hash output logic
window.addEventListener('DOMContentLoaded', function() {
    const friendUsernameInput = document.getElementById('friend-username-input');
    const hashOutput = document.getElementById('hash-output');
    const verifyBtn = document.getElementById('verify-new-user-btn');
    const generateBtn = document.getElementById('generate-hash-btn');

    // Always update the button state when the hash changes
    function checkHashAndToggleVerifyBtn() {
        if (hashOutput.value && hashOutput.value !== "No friend username entered..." && hashOutput.value !== "Ready to generate hash") {
            verifyBtn.disabled = false;
            verifyBtn.style.display = 'inline-block';
        } else {
            verifyBtn.disabled = true;
            verifyBtn.style.display = 'none';
        }
    }

    // Listen for changes to the hash output
    const observer = new MutationObserver(checkHashAndToggleVerifyBtn);
    observer.observe(hashOutput, { attributes: true, attributeFilter: ['value'] });

    // Also check on input and after generate button is pressed
    friendUsernameInput.addEventListener('input', checkHashAndToggleVerifyBtn);
    generateBtn.addEventListener('click', function() {
        setTimeout(checkHashAndToggleVerifyBtn, 50);
    });

    // Initial check
    checkHashAndToggleVerifyBtn();
});
