const form = document.querySelector("[data-audit-form]");
form.addEventListener("submit", () => {
    form.querySelector("button").disabled = true;
    form.querySelector("[data-audit-status]").hidden = false;
});
