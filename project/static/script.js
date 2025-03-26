// static/script.js

async function signup(event) {
    event.preventDefault();
    const data = {
        username: document.getElementById("username").value,
        email: document.getElementById("email").value,
        password: document.getElementById("password").value,
        role: document.getElementById("role").value,
        sensitive_data: "Confidential"
    };

    const response = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    alert(result.message);
    window.location.href = "/login";
}

async function login(event) {
    event.preventDefault();
    const data = {
        email: document.getElementById("email").value,
        password: document.getElementById("password").value,
    };

    const response = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });

    const result = await response.json();
    if (response.ok) {
        localStorage.setItem("token", result.access_token);
        const tokenData = JSON.parse(atob(result.access_token.split(".")[1]));
        const role = tokenData.role;

        if (role === "superadmin") window.location.href = "/superadmin";
        else if (role === "manager") window.location.href = "/manager";
        else window.location.href = "/user";
    } else {
        alert(result.message);
    }
}

async function fetchDashboard(endpoint) {
    const token = localStorage.getItem("token");
    if (!token) return (window.location.href = "/login");

    const response = await fetch(endpoint, {
        headers: { Authorization: "Bearer " + token },
    });

    const result = await response.json();
    document.getElementById("message").innerText = result.message;
}

function logout() {
    localStorage.removeItem("token");
    window.location.href = "/login";
}

document.addEventListener("DOMContentLoaded", function () {
    if (document.getElementById("signupForm")) {
        document.getElementById("signupForm").addEventListener("submit", signup);
    }
    if (document.getElementById("loginForm")) {
        document.getElementById("loginForm").addEventListener("submit", login);
    }
});
