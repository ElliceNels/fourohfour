function updateFileInfo(input) {
    if (input.files.length > 0) {
        const file = input.files[0];
        const maxSize = 10 * 1024 * 1024; // 10 MB in bytes

        if (file.size > maxSize) {
            alert('File is too large! Maximum allowed size is 10MB.');
            input.value = ''; // Clear the file input
            // Optionally, hide details and confirm button if previously shown
            document.getElementById('upload-details').style.display = 'none';
            document.getElementById('upload-instructions').style.display = 'none';
            document.getElementById('confirm-btn').style.display = 'none';
            return;
        }

        const fileName = document.getElementById('file-name');
        const fileType = document.getElementById('file-type');
        const fileSize = document.getElementById('file-size');
        const uploadDetails = document.getElementById('upload-details');
        const uploadInstructions = document.getElementById('upload-instructions');
        const confirmBtn = document.getElementById('confirm-btn');

        fileName.value = file.name;
        // Use MIME type instead of file extension
        fileType.value = file.type || '-';
        fileSize.value = `${file.size} bytes`;
        
        uploadDetails.style.display = 'block';
        uploadInstructions.style.display = 'block';
        confirmBtn.style.display = 'inline-block';
    }
}

function triggerBrowse() {
    document.getElementById('file-input').click();
}
