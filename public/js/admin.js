(async function bootstrapAdmin() {
  try {
    const user = await loadCurrentUser();

    //changed error logic, actually does security check not just a warning
    if (!user || user.role !== "admin") {
      document.getElementById("admin-warning").textContent =
        "Admin access required.";
      return;
    }
    document.getElementById("admin-warning").textContent =
      "Authenticated as admin.";

    const result = await api("/api/admin/users");
    //removal of innerHTML, dom safe reconstruction
    const table = document.getElementById("admin-users");
    table.replaceChildren();

    result.users.forEach((e) => {
      const tr = document.createElement("tr");

      [e.id, e.username, e.role, e.displayName, e.noteCount]
        .forEach((val) => {
          const td = document.createElement("td");
          td.textContent = val;
          tr.appendChild(td);
        });

      table.appendChild(tr);
    });
  } catch (error) {
    document.getElementById("admin-warning").textContent = error.message;
  }
})();
