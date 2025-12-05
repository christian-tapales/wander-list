// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            e.preventDefault();
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});

// Button hover ripple effect (simple)
document.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('mouseenter', () => {
        btn.style.boxShadow = '0 6px 24px rgba(45,108,223,0.15)';
    });
    btn.addEventListener('mouseleave', () => {
        btn.style.boxShadow = '0 2px 8px rgba(45,108,223,0.08)';
    });
});
