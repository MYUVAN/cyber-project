document.addEventListener("DOMContentLoaded", function () {
    // 1. Drag and Drop File Upload Portal
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const fileSelectBtn = document.getElementById("file-select-btn");
    const fileDetails = document.getElementById("file-details");
    const selectedFileName = document.getElementById("selected-file-name");
    const uploadForm = document.getElementById("upload-form");

    if (dropZone && fileInput) {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        // Add/remove hover styling classes
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, unhighlight, false);
        });

        // Handle drop event
        dropZone.addEventListener('drop', handleDrop, false);

        // Click to open file dialog
        fileSelectBtn.addEventListener('click', function() {
            fileInput.click();
        });

        // File input change event
        fileInput.addEventListener('change', function() {
            handleFiles(this.files);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        function highlight() {
            dropZone.classList.add('dragover');
        }

        function unhighlight() {
            dropZone.classList.remove('dragover');
        }

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(files);
        }

        function handleFiles(files) {
            if (files.length > 0) {
                const file = files[0];
                fileInput.files = files; // Bind file to standard input
                
                // Display file details
                selectedFileName.textContent = `${file.name} (${formatBytes(file.size)})`;
                fileDetails.classList.remove('d-none');
                
                // Check extension warning
                const allowedExtensions = ['.exe', '.zip', '.pdf', '.docx', '.js', '.txt'];
                const fileExt = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
                const warningDiv = document.getElementById("ext-warning");
                
                if (!allowedExtensions.includes(fileExt)) {
                    if (warningDiv) {
                        warningDiv.textContent = `Warning: Extension "${fileExt}" is not standard, but the sandbox will simulate it deterministically.`;
                        warningDiv.classList.remove('d-none');
                    }
                } else {
                    if (warningDiv) warningDiv.classList.add('d-none');
                }
            }
        }
    }

    // Helper: size formatting
    function formatBytes(bytes, decimals = 2) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    // 2. Beginner-Friendly Security Explanation Typewriter Effect
    const typewriterElement = document.getElementById("typewriter-explanation");
    if (typewriterElement) {
        const fullText = typewriterElement.getAttribute("data-text");
        typewriterElement.textContent = ""; // Clear initial
        let index = 0;
        const speed = 20; // ms per character

        function type() {
            if (index < fullText.length) {
                typewriterElement.textContent += fullText.charAt(index);
                index++;
                setTimeout(type, speed);
            }
        }
        
        // Start animation after a slight delay
        setTimeout(type, 500);
    }
    
    // 3. Dynamic Execution timeline visual delay (simulation)
    const logEntries = document.querySelectorAll(".log-entry");
    if (logEntries.length > 0) {
        logEntries.forEach((entry, idx) => {
            entry.style.opacity = 0;
            entry.style.transform = "translateX(-10px)";
            entry.style.transition = "all 0.3s ease";
            
            // Incrementally show log entries like a live terminal running
            setTimeout(() => {
                entry.style.opacity = 1;
                entry.style.transform = "translateX(0)";
            }, idx * 400); // 400ms delay per line
        });
    }
});
