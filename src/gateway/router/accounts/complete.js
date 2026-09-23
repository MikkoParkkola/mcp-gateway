// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// The completion page's only script (design §8.3): a form cannot send DELETE.
"use strict";
for (const button of document.querySelectorAll("button[data-account]")) {
  button.addEventListener("click", async () => {
    button.disabled = true;
    const url = "/accounts/v1/connections/" + encodeURIComponent(button.dataset.account);
    let ok = false;
    try {
      ok = (await fetch(url, { method: "DELETE", credentials: "same-origin" })).ok;
    } catch (_) {}
    button.textContent = ok ? "Disconnected" : "Failed; reload and retry";
  });
}
