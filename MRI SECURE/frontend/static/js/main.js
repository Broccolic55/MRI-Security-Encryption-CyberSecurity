// frontend/static/js/main.js

document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide alert messages after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => {
                alert.style.display = 'none';
            }, 500);
        }, 5000);
    });

    // File input preview for admin dashboard
    const mriInput = document.getElementById('mri_image');
    const coverInput = document.getElementById('cover_image');
    
    if (mriInput) {
        mriInput.addEventListener('change', function() {
            validateFileSize(this, 5); // 5MB limit
        });
    }
    
    if (coverInput) {
        coverInput.addEventListener('change', function() {
            validateFileSize(this, 5); // 5MB limit
        });
    }
    
    // OTP input enhancement
    const otpInput = document.getElementById('otp');
    if (otpInput) {
        otpInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
        });
    }
    
    // Confirmation for logout
    const logoutLink = document.querySelector('a[href="/logout"]');
    if (logoutLink) {
        logoutLink.addEventListener('click', function(e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
            }
        });
    }
    
    // Hamburger menu functionality
    const hamburgerMenu = document.getElementById('hamburger-menu');
    const sidePanel = document.getElementById('side-panel');
    const closePanel = document.getElementById('close-panel');
    const overlay = document.getElementById('overlay');
    
    if (hamburgerMenu) {
        hamburgerMenu.addEventListener('click', function() {
            sidePanel.classList.add('active');
            overlay.classList.add('active');
        });
    }
    
    if (closePanel) {
        closePanel.addEventListener('click', function() {
            sidePanel.classList.remove('active');
            overlay.classList.remove('active');
        });
    }
    
    if (overlay) {
        overlay.addEventListener('click', function() {
            sidePanel.classList.remove('active');
            overlay.classList.remove('active');
        });
    }
    
    // Integrity verification functionality
    const verifyDataBtn = document.getElementById('verify-data-btn');
    const verifyPatientId = document.getElementById('verify-patient-id');
    const integrityResults = document.getElementById('integrity-results');
    
    if (verifyDataBtn) {
        verifyDataBtn.addEventListener('click', function() {
            const patientId = verifyPatientId.value.trim();
            
            if (!patientId) {
                alert('Please enter a patient ID');
                return;
            }
            
            // Show loading state
            integrityResults.innerHTML = '<p>Verifying data integrity...</p>';
            
            // Fetch integrity data from the server
            fetch(`/admin/verify-integrity?patient_id=${encodeURIComponent(patientId)}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        integrityResults.innerHTML = `<p class="alert alert-error">${data.error}</p>`;
                    } else {
                        // Determine overall status - if any file is unverified, the overall status is unverified
                        const isAllVerified = data.tampered_files_count === 0;
                        const statusClass = isAllVerified ? 'status-verified' : 'status-unverified';
                        const statusText = isAllVerified ? 'VERIFIED' : 'UNVERIFIED';
                        const totalFiles = data.files.length;
                        
                        // Create simplified result with only the overall status
                        let resultsHTML = `
                            <div class="integrity-summary">
                                <h4>Patient ID: ${patientId}</h4>
                                <div class="status-box ${statusClass}">
                                    <p class="status-title">Status: <span class="status-text">${statusText}</span></p>
                                    <p class="status-detail">Files checked: ${totalFiles}</p>
                                </div>`;
                        
                        // Add warning if there are integrity issues
                        if (!isAllVerified) {
                            resultsHTML += `
                                <div class="integrity-warning">
                                    <p><i class="fas fa-exclamation-triangle"></i> Warning: ${data.tampered_files_count} file(s) with integrity issues detected.</p>
                                    ${data.alert_sent ? '<p><i class="fas fa-envelope"></i> Patient has been notified via email.</p>' : ''}
                                </div>`;
                        }
                        
                        resultsHTML += '</div>';
                        integrityResults.innerHTML = resultsHTML;
                    }
                })
                .catch(error => {
                    integrityResults.innerHTML = `<p class="alert alert-error">Error: ${error.message}</p>`;
                });
        });
    }
});

// Validate file size
function validateFileSize(input, maxSize) {
    const file = input.files[0];
    if (file) {
        const fileSize = file.size / 1024 / 1024; // Size in MB
        if (fileSize > maxSize) {
            alert(`File size exceeds ${maxSize}MB. Please choose a smaller file.`);
            input.value = ''; // Clear the input
        }
    }
}