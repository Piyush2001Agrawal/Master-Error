document.addEventListener('DOMContentLoaded', function() {
    // Ensure initially expanded items have their max-height set
    document.querySelectorAll('.accordion-collapse.show').forEach(collapse => {
        collapse.style.maxHeight = collapse.scrollHeight + "px";
    });

    const faqAccordion = document.getElementById('faqAccordion');
    if (faqAccordion) {
        faqAccordion.addEventListener('click', event => {
            const target = event.target;
            if (target.classList.contains('dropdown-toggle')) {
                const dropdownMenu = target.nextElementSibling;
                if (dropdownMenu && dropdownMenu.classList.contains('dropdown-menu')) {
                    const isExpanded = target.getAttribute('aria-expanded') === 'true';
                    target.setAttribute('aria-expanded', !isExpanded);
                    dropdownMenu.style.display = isExpanded ? 'none' : 'block';
                }
            }
        });

        faqAccordion.addEventListener('show.bs.collapse', event => {
            faqAccordion.querySelectorAll('.accordion-collapse.show').forEach(collapse => {
                if (collapse !== event.target) {
                    collapse.classList.remove('show');
                    collapse.style.maxHeight = null;
                    const button = document.querySelector(`[data-bs-target="#${collapse.id}"]`);
                    if (button) {
                        button.classList.add('collapsed');
                        button.setAttribute('aria-expanded', 'false');
                    }
                }
            });
            event.target.style.maxHeight = event.target.scrollHeight + "px";
            const button = document.querySelector(`[data-bs-target="#${event.target.id}"]`);
            if (button) {
                button.classList.remove('collapsed');
                button.setAttribute('aria-expanded', 'true');
            }
        });

        faqAccordion.addEventListener('hide.bs.collapse', event => {
            event.target.style.maxHeight = null;
            const button = document.querySelector(`[data-bs-target="#${event.target.id}"]`);
            if (button) {
                button.classList.add('collapsed');
                button.setAttribute('aria-expanded', 'false');
            }
        });
    }

    const dropdownToggles = document.querySelectorAll('.dropdown-toggle');

    dropdownToggles.forEach(toggle => {
        toggle.addEventListener('click', function(event) {
            event.preventDefault();
            const dropdownMenu = this.nextElementSibling;

            if (dropdownMenu && dropdownMenu.classList.contains('dropdown-menu')) {
                const isVisible = dropdownMenu.style.display === 'block';

                // Hide all other dropdowns
                document.querySelectorAll('.dropdown-menu').forEach(menu => {
                    menu.style.display = 'none';
                });

                // Toggle the clicked dropdown
                dropdownMenu.style.display = isVisible ? 'none' : 'block';
            }
        });
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', function(event) {
        if (!event.target.closest('.dropdown')) {
            document.querySelectorAll('.dropdown-menu').forEach(menu => {
                menu.style.display = 'none';
            });
        }
    });
});