/**
 * Browser-side login and logout behaviour.
 * The database is intentionally queried by app.py, not by browser code.
 */

const loginForm = document.querySelector("#login-form");
const logoutButton = document.querySelector("#logout-button");

function showLoginMessage(message, invalidFields = []) {
    const messageElement = document.querySelector("#login-message");
    if (!messageElement) return;

    messageElement.textContent = message;
    messageElement.hidden = false;

    document.querySelectorAll("#login-form input").forEach((input) => {
        input.classList.toggle("is-invalid", invalidFields.includes(input.name));
        input.setAttribute("aria-invalid", String(invalidFields.includes(input.name)));
    });
}

function clearLoginMessage() {
    const messageElement = document.querySelector("#login-message");
    if (messageElement) {
        messageElement.hidden = true;
        messageElement.textContent = "";
    }

    document.querySelectorAll("#login-form input").forEach((input) => {
        input.classList.remove("is-invalid");
        input.removeAttribute("aria-invalid");
    });
}

if (loginForm) {
    const loginButton = document.querySelector("#login-button");

    loginForm.addEventListener("input", clearLoginMessage);

    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        clearLoginMessage();

        const username = loginForm.username.value.trim();
        const password = loginForm.password.value;
        const missingFields = [];

        if (!username) missingFields.push("username");
        if (!password) missingFields.push("password");

        if (missingFields.length) {
            showLoginMessage("Enter both your username and password.", missingFields);
            return;
        }

        loginButton.disabled = true;
        loginButton.textContent = "Checking...";

        try {
            const response = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });
            const result = await response.json();

            if (response.ok && result.success) {
                window.location.assign("/welcome.html");
                return;
            }

            showLoginMessage(result.message || "Unable to sign in.", result.invalid_fields || []);
        } catch {
            showLoginMessage(
                "Login could not be verified. Start app.py and open http://localhost:8000.",
            );
        } finally {
            loginButton.disabled = false;
            loginButton.textContent = "Log in";
        }
    });
}

if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
        logoutButton.disabled = true;

        try {
            await fetch("/api/logout", { method: "POST" });
        } finally {
            window.location.assign("/");
        }
    });
}
