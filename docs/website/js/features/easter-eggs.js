const EasterEgg = (() => {
  const toastId = "egg-toast";
  const secretQueries = {
    asrfrb: () => {
      showToast("Alias recognized: asrfrb");
      spawnConfetti(20);
    },
    reconparty: () => {
      showToast("Recon party mode activated");
      spawnConfetti(26);
    },
    upupdowndownleftrightleftrightba: () => {
      activateOverdrive({ message: "Konami accepted: recon overdrive", duration: 14000, confettiCount: 30 });
    },
    overdrivesync: () => {
      activateOverdrive({
        message: "over drive sync - ribbons fall",
        duration: 14000,
        confettiCount: 30
      });
    }
  };

  let logoTapCount = 0;
  let logoTapTimer = null;
  let nameTapCount = 0;
  let nameTapTimer = null;
  let searchTapCount = 0;
  let searchTapTimer = null;
  let footerTapCount = 0;
  let footerTapTimer = null;
  let longPressTimer = null;
  let menuLongPressTimer = null;
  let overdriveTimer = null;
  let ghostModeTimer = null;
  let signalLockTimer = null;
  let toastTimer = null;
  let lastSecretQuery = "";

  function ensureToast() {
    let toast = document.getElementById(toastId);
    if (toast) {
      return toast;
    }

    toast = document.createElement("div");
    toast.id = toastId;
    toast.className = "egg-toast";
    toast.setAttribute("aria-live", "polite");
    DocsElements.body.appendChild(toast);
    return toast;
  }

  function showToast(message) {
    const toast = ensureToast();
    toast.textContent = message;
    toast.classList.add("show");

    if (toastTimer) {
      window.clearTimeout(toastTimer);
    }

    toastTimer = window.setTimeout(() => {
      toast.classList.remove("show");
    }, 2200);
  }

  function spawnConfetti(options = {}) {
    const count = Number.isFinite(options) ? options : (Number.isFinite(options.count) ? options.count : 20);
    const layer = document.createElement("div");
    layer.className = "egg-confetti-layer";
    DocsElements.body.appendChild(layer);

    const colors = ["#ff5a5f", "#ffd166", "#7ee787", "#79c0ff", "#c297ff"];
    const total = Math.max(8, Math.min(count, 48));

    for (let i = 0; i < total; i += 1) {
      const bit = document.createElement("span");
      bit.className = "egg-confetti";
      bit.style.left = `${Math.random() * 100}%`;
      bit.style.background = colors[i % colors.length];
      bit.style.setProperty("--egg-drift", `${(Math.random() * 180) - 90}px`);
      bit.style.animationDuration = `${2.2 + (Math.random() * 1.8)}s`;
      bit.style.animationDelay = `${Math.random() * 0.25}s`;
      layer.appendChild(bit);
    }

    window.setTimeout(() => {
      layer.remove();
    }, 3200);
  }

  function activateOverdrive(options = {}) {
    const message = options.message || "Recon overdrive enabled for 12 seconds";
    const duration = Number.isFinite(options.duration) ? options.duration : 12000;
    const confettiCount = Number.isFinite(options.confettiCount) ? options.confettiCount : 24;

    DocsElements.body.classList.add("egg-overdrive");
    showToast(message);
    spawnConfetti(confettiCount);

    if (overdriveTimer) {
      window.clearTimeout(overdriveTimer);
    }
    overdriveTimer = window.setTimeout(() => {
      DocsElements.body.classList.remove("egg-overdrive");
    }, duration);
  }

  function toggleBlueprintMode() {
    const enabled = DocsElements.body.classList.toggle("egg-blueprint");
    showToast(enabled ? "Blueprint mode enabled" : "Blueprint mode disabled");
  }

  function activateSignalLock(duration = 4200) {
    DocsElements.body.classList.add("egg-signal-lock");
    showToast("signal lock acquired");
    spawnConfetti(14);

    if (signalLockTimer) {
      window.clearTimeout(signalLockTimer);
    }
    signalLockTimer = window.setTimeout(() => {
      DocsElements.body.classList.remove("egg-signal-lock");
    }, duration);
  }

  function activateGhostMode(duration = 10000) {
    DocsElements.body.classList.add("egg-ghost-mode");
    showToast("ghost mode active");

    if (ghostModeTimer) {
      window.clearTimeout(ghostModeTimer);
    }
    ghostModeTimer = window.setTimeout(() => {
      DocsElements.body.classList.remove("egg-ghost-mode");
    }, duration);
  }

  function toggleCleanScreen() {
    const enabled = DocsElements.body.classList.toggle("egg-clean-screen");
    showToast(enabled ? "clean screen enabled" : "clean screen disabled");
  }

  function bindLogoTapCombo() {
    if (!DocsElements.topbarLogo) {
      return;
    }

    DocsElements.topbarLogo.addEventListener("click", () => {
      logoTapCount += 1;
      if (logoTapTimer) {
        window.clearTimeout(logoTapTimer);
      }

      logoTapTimer = window.setTimeout(() => {
        logoTapCount = 0;
      }, 1800);

      if (logoTapCount >= 5) {
        logoTapCount = 0;
        activateOverdrive({ message: "Topbar overdrive unlocked", duration: 9000, confettiCount: 20 });
      }
    });
  }

  function bindNameTapCombo() {
    if (!DocsElements.topbarName) {
      return;
    }

    DocsElements.topbarName.addEventListener("click", () => {
      nameTapCount += 1;
      if (nameTapTimer) {
        window.clearTimeout(nameTapTimer);
      }
      nameTapTimer = window.setTimeout(() => {
        nameTapCount = 0;
      }, 1600);

      if (nameTapCount >= 4) {
        nameTapCount = 0;
        activateSignalLock();
      }
    });
  }

  function bindVersionLongPress() {
    if (!DocsElements.topbarVersion) {
      return;
    }

    const startPress = (event) => {
      if (event.type === "mousedown" && event.button !== 0) {
        return;
      }
      if (longPressTimer) {
        window.clearTimeout(longPressTimer);
      }
      longPressTimer = window.setTimeout(() => {
        toggleBlueprintMode();
      }, 800);
    };

    const cancelPress = () => {
      if (longPressTimer) {
        window.clearTimeout(longPressTimer);
        longPressTimer = null;
      }
    };

    DocsElements.topbarVersion.addEventListener("mousedown", startPress);
    DocsElements.topbarVersion.addEventListener("mouseup", cancelPress);
    DocsElements.topbarVersion.addEventListener("mouseleave", cancelPress);
    DocsElements.topbarVersion.addEventListener("touchstart", startPress, { passive: true });
    DocsElements.topbarVersion.addEventListener("touchend", cancelPress);
    DocsElements.topbarVersion.addEventListener("touchcancel", cancelPress);
  }

  function bindMenuLongPress() {
    if (!DocsElements.menuToggle) {
      return;
    }

    const startPress = (event) => {
      if (event.type === "mousedown" && event.button !== 0) {
        return;
      }
      if (menuLongPressTimer) {
        window.clearTimeout(menuLongPressTimer);
      }
      menuLongPressTimer = window.setTimeout(() => {
        activateGhostMode();
      }, 900);
    };

    const cancelPress = () => {
      if (menuLongPressTimer) {
        window.clearTimeout(menuLongPressTimer);
        menuLongPressTimer = null;
      }
    };

    DocsElements.menuToggle.addEventListener("mousedown", startPress);
    DocsElements.menuToggle.addEventListener("mouseup", cancelPress);
    DocsElements.menuToggle.addEventListener("mouseleave", cancelPress);
    DocsElements.menuToggle.addEventListener("touchstart", startPress, { passive: true });
    DocsElements.menuToggle.addEventListener("touchend", cancelPress);
    DocsElements.menuToggle.addEventListener("touchcancel", cancelPress);
  }

  function bindSearchTapCombo() {
    if (!DocsElements.searchInput) {
      return;
    }

    DocsElements.searchInput.addEventListener("click", () => {
      searchTapCount += 1;
      if (searchTapTimer) {
        window.clearTimeout(searchTapTimer);
      }
      searchTapTimer = window.setTimeout(() => {
        searchTapCount = 0;
      }, 1500);

      if (searchTapCount >= 3) {
        searchTapCount = 0;
        toggleCleanScreen();
      }
    });
  }

  function bindFooterTapCombo() {
    if (!DocsElements.siteFooter) {
      return;
    }

    DocsElements.siteFooter.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLElement)) {
        return;
      }

      const tapTarget = target.closest(".footer-col-title");
      if (!tapTarget) {
        return;
      }

      footerTapCount += 1;
      if (footerTapTimer) {
        window.clearTimeout(footerTapTimer);
      }
      footerTapTimer = window.setTimeout(() => {
        footerTapCount = 0;
      }, 1600);

      if (footerTapCount >= 3) {
        footerTapCount = 0;
        showToast("Hidden trace: keep calm, recon smart");
        spawnConfetti(16);
      }
    });
  }

  function onSearchInput(value = "") {
    const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, "");
    const action = secretQueries[normalized];
    if (!action) {
      lastSecretQuery = "";
      return;
    }

    if (lastSecretQuery === normalized) {
      return;
    }

    lastSecretQuery = normalized;
    action();
  }

  function bind() {
    bindLogoTapCombo();
    bindNameTapCombo();
    bindVersionLongPress();
    bindMenuLongPress();
    bindSearchTapCombo();
    bindFooterTapCombo();
  }

  return { bind, onSearchInput, activateOverdrive, showToast, spawnConfetti };
})();
