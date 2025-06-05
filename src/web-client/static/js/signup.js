// JavaScript for signup.html
function togglePassword() {
    const pwd = document.getElementById('password');
    const confirm = document.getElementById('confirm_password');
    const btn = document.getElementById('show-btn');
    if (pwd.type === 'password') {
        pwd.type = 'text';
        confirm.type = 'text';
        btn.textContent = 'Hide';
    } else {
        pwd.type = 'password';
        confirm.type = 'password';
        btn.textContent = 'Show';
    }
}

function showProgressAndDisableBtn() {
    document.getElementById('signup-btn').disabled = true;
    document.getElementById('signup-btn').textContent = 'Registering...';
}
