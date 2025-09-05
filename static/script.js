document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(msg => {
        setTimeout(() => {
            msg.style.transition = 'all 0.3s ease';
            msg.style.transform = 'translateX(150%)';
            setTimeout(() => msg.remove(), 300);
        }, 5000);
    });

    // Copy short URL to clipboard
    document.querySelectorAll('.short-url a').forEach(link => {
        link.addEventListener('click', function(e) {
            if (e.ctrlKey || e.metaKey) return; // Allow normal click behavior
            
            e.preventDefault();
            const url = this.href;
            navigator.clipboard.writeText(url).then(() => {
                alert('URL copied to clipboard!');
                window.open(url, '_blank');
            });
        });
    });
});