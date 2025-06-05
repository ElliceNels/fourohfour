function togglePassword() {
    const oldPwd = document.getElementById('old_password');
    const newPwd = document.getElementById('new_password');
    const confirm = document.getElementById('confirm_password');
    const btn = document.getElementById('show-btn');
    if (oldPwd.type === 'password') {
        oldPwd.type = 'text';
        newPwd.type = 'text';
        confirm.type = 'text';
        btn.textContent = 'Hide';
    } else {
        oldPwd.type = 'password';
        newPwd.type = 'password';
        confirm.type = 'password';
        btn.textContent = 'Show';
    }
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