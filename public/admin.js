const socket = io();

socket.on("newAction", (data) => {
  console.log("⚡ Real-time attack:", data);
  fetchLogs();
});

let chart;

async function fetchLogs() {
  const res = await fetch("/admin/logs");
  const logs = await res.json();

  document.getElementById("totalAttacks").innerText = logs.length;

  if (logs.length > 0) {
    const latest = logs[logs.length - 1];

    document.getElementById("latestIP").innerText = latest.ipAddress;
    document.getElementById("latestTime").innerText = latest.time;
  }

  const table = document.getElementById("logTable");
  table.innerHTML = "";

  logs.forEach((log) => {
    table.innerHTML += `
    
<tr onclick="openProfile('${log.ipAddress}')" 
class="hover:bg-gray-800 transition duration-200 cursor-pointer">

<td class="p-3">${log.username}</td>

<td class="p-3 text-red-400">${log.password}</td>

<td class="p-3 text-yellow-400">${log.ipAddress}</td>

<td class="p-3">${log.country}</td>

<td class="p-3">${log.city}</td>

<td class="p-3">${log.isp}</td>

<td class="p-3 text-gray-300">${log.time}</td>

<td class="p-3">

<button onclick="event.stopPropagation(); blockIP('${log.ipAddress}')"
class="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded-lg shadow-md">

Block

</button>

</td>

</tr>

`;
  });

  renderChart(logs);
}

function openProfile(ip) {
  window.location.href = "/hacker.html?ip=" + ip;
}

function renderChart(logs) {
  const ctx = document.getElementById("attackChart");

  if (chart) {
    chart.destroy();
  }

  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: logs.map((_, i) => `#${i + 1}`),
      datasets: [
        {
          label: "Attack Count",
          data: logs.map((_, i) => i + 1),
          borderColor: "#5ec576",
          backgroundColor: "rgba(94,197,118,0.2)",
          tension: 0.4,
          fill: true,
        },
      ],
    },
    options: {
      plugins: {
        legend: {
          labels: { color: "white" },
        },
      },
      scales: {
        x: {
          ticks: { color: "white" },
        },
        y: {
          ticks: { color: "white" },
        },
      },
    },
  });
}

function blockIP(ip) {
  alert("🚫 Blocking IP: " + ip);
}

fetchLogs();
