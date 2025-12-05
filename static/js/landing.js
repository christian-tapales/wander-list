// landing.js
document.addEventListener("DOMContentLoaded", () => {
    const fadeElems = document.querySelectorAll(".feature-card");

    fadeElems.forEach(card => {
        card.style.opacity = 0;
        card.style.transform = "translateY(20px)";
    });

    const revealOnScroll = () => {
        fadeElems.forEach(card => {
            const rect = card.getBoundingClientRect();

            if (rect.top < window.innerHeight - 80) {
                card.style.transition = "0.6s ease";
                card.style.opacity = 1;
                card.style.transform = "translateY(0)";
            }
        });
    };

    window.addEventListener("scroll", revealOnScroll);
    revealOnScroll();
});
