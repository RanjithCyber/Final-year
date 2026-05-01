const socket = io();

const params = new URLSearchParams(window.location.search);
const ip = params.get("ip");

async function loadActions() {
  const res = await fetch("/admin/hacker/" + ip);
  const data = await res.json();

  const table = document.getElementById("actions");
  table.innerHTML = "";

  if (!data.actions || data.actions.length === 0) {
    table.innerHTML = `
<tr>
<td colspan="3" style="text-align:center; opacity:0.6;">
No activity recorded
</td>
</tr>
`;

    return;
  }

  data.actions.forEach((a) => {
    let details = "";
    let badge = "";

    if (a.type === "mouse") {
      details = `x:${a.x} y:${a.y}`;
      badge = "badge-mouse";
    }

    if (a.type === "key") {
      details = `key:${a.key}`;
      badge = "badge-key";
    }

    if (a.type === "page") {
      details = `page:${a.page}`;
      badge = "badge-page";
    }

    table.innerHTML += `
<tr>

<td>
<span class="badge ${badge}">
${a.type}
</span>
</td>

<td>${details}</td>

<td>${a.time}</td>

</tr>
`;
  });
}

loadActions();

// refresh every 2 seconds
setInterval(loadActions, 2000);

// real-time socket trigger
socket.on("newAction", (data) => {
  if (data.ip === ip) {
    loadActions();
  }
});
