// JavaScript for login.html
function togglePassword() {
    const pwd = document.getElementById('password');
    const btn = document.getElementById('show-btn');
    if (pwd.type === 'password') {
        pwd.type = 'text';
        btn.textContent = 'Hide';
    } else {
        pwd.type = 'password';
        btn.textContent = 'Show';
    }
}

function showLoginProgressAndDisableBtn() {
    var btn = document.getElementById('login-btn');
    btn.disabled = true;
    btn.textContent = 'Logging in...';
}
