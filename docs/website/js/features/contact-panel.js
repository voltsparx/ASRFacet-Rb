const ContactPanel = (() => {
  let openContainer = null;

  function close(container) {
    if (!container) {
      return;
    }

    const toggle = container.querySelector(".topbar-contact-toggle");
    const popover = container.querySelector(".topbar-contact-popover");
    if (toggle) {
      toggle.setAttribute("aria-expanded", "false");
    }
    if (popover) {
      popover.classList.remove("is-open");
      popover.hidden = true;
      popover.setAttribute("aria-hidden", "true");
      popover.style.display = "none";
    }
    if (openContainer === container) {
      openContainer = null;
    }
  }

  function closeOpen() {
    if (openContainer) {
      close(openContainer);
    }
  }

  function bind() {
    const containers = document.querySelectorAll(".topbar-contact");
    if (containers.length === 0) {
      return;
    }

    containers.forEach((container) => {
      const toggle = container.querySelector(".topbar-contact-toggle");
      const popover = container.querySelector(".topbar-contact-popover");
      if (!toggle || !popover) {
        return;
      }

      popover.classList.remove("is-open");
      popover.hidden = true;
      popover.setAttribute("aria-hidden", "true");
      popover.style.display = "none";
      toggle.setAttribute("aria-expanded", "false");

      toggle.addEventListener("click", (event) => {
        event.preventDefault();
        const shouldOpen = !popover.classList.contains("is-open");
        closeOpen();
        popover.classList.toggle("is-open", shouldOpen);
        popover.hidden = !shouldOpen;
        popover.setAttribute("aria-hidden", shouldOpen ? "false" : "true");
        popover.style.display = shouldOpen ? "grid" : "none";
        toggle.setAttribute("aria-expanded", shouldOpen ? "true" : "false");
        openContainer = shouldOpen ? container : null;
      });
    });

    document.addEventListener("click", (event) => {
      if (!openContainer) {
        return;
      }
      if (openContainer.contains(event.target)) {
        return;
      }
      closeOpen();
    });
  }

  return { bind, closeOpen };
})();
