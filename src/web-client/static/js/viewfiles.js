// JavaScript for viewfiles.html
function switchTab(tab) {
    document.getElementById('owned-btn').classList.remove('active');
    document.getElementById('shared-btn').classList.remove('active');
    document.getElementById('owned-section').style.display = 'none';
    document.getElementById('shared-section').style.display = 'none';
    if (tab === 'owned') {
        document.getElementById('owned-btn').classList.add('active');
        document.getElementById('owned-section').style.display = 'block';
    } else {
        document.getElementById('shared-btn').classList.add('active');
        document.getElementById('shared-section').style.display = 'block';
    }
}
window.onload = function() {
    switchTab('owned');
};
