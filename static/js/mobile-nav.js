// Mobile Navigation Handler
(function () {
    'use strict';

    function initMobileNav() {
        // Check if we're on a dashboard page with sidebar
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        // Create mobile menu toggle button
        const menuToggle = document.createElement('button');
        menuToggle.className = 'mobile-menu-toggle';
        menuToggle.setAttribute('aria-label', 'Toggle Navigation Menu');
        menuToggle.innerHTML = `
            <span></span>
            <span></span>
            <span></span>
        `;

        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'sidebar-overlay';

        // Insert elements
        document.body.insertBefore(menuToggle, document.body.firstChild);
        document.body.insertBefore(overlay, document.body.firstChild);

        // Toggle functionality
        function toggleMenu() {
            sidebar.classList.toggle('active');
            menuToggle.classList.toggle('active');
            overlay.classList.toggle('active');
            document.body.style.overflow = sidebar.classList.contains('active') ? 'hidden' : '';
        }

        // Event listeners
        menuToggle.addEventListener('click', toggleMenu);
        overlay.addEventListener('click', toggleMenu);

        // Close menu when clicking nav links
        const navLinks = sidebar.querySelectorAll('.nav-menu a, .nav-menu button');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    toggleMenu();
                }
            });
        });

        // Handle window resize
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                if (window.innerWidth > 768) {
                    sidebar.classList.remove('active');
                    menuToggle.classList.remove('active');
                    overlay.classList.remove('active');
                    document.body.style.overflow = '';
                }
            }, 250);
        });
    }

    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMobileNav);
    } else {
        initMobileNav();
    }
})();
