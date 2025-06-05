// JavaScript for resetpassword.html
function togglePassword() {
    const fields = document.querySelectorAll('.password-input');
    fields.forEach(field => {
        field.type = field.type === 'password' ? 'text' : 'password';
    });
}

function showResetProgressAndDisableBtn() {
    var btn = document.getElementById('update-password-btn');
    btn.disabled = true;
    btn.textContent = 'Updating password...';
}

document.addEventListener('DOMContentLoaded', function() {
    var form = document.getElementById('reset-form');
    if (form) {
        form.addEventListener('submit', showResetProgressAndDisableBtn);
    }
});
