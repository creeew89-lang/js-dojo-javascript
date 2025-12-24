const SALT_BYTES = 16;
const KEY_BYTES = 256;
const ITERATIONS = 100_000;

async function deriveKey(pass, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(pass),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: KEY_BYTES },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(text)
  );
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(ct)) };
}

async function decrypt(payloadObj, key) {
  const iv = new Uint8Array(payloadObj.iv);
  const data = new Uint8Array(payloadObj.data);
  const dec = new TextDecoder();
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );
  return dec.decode(pt);
}

let KEY = null;   
let VAULT = [];   

const $ = id => document.getElementById(id);

async function unlock() {
  const pass = $("master").value;
  if (!pass) return flash("Passphrase required");
  const salt = await getSalt();
  KEY = await deriveKey(pass, salt);
  try {
    const raw = localStorage.getItem("vault");
    if (raw) {
      const payload = JSON.parse(raw);
      const plain = await decrypt(payload, KEY);
      VAULT = JSON.parse(plain);
    }
    $("unlock").style.display = "none";
    $("vault").style.display = "block";
    render();
  } catch (e) {
    flash("Wrong passphrase or corrupted vault");
    KEY = null;
  }
}

function logout() {
  KEY = null;
  VAULT = [];
  $("vault").style.display = "none";
  $("unlock").style.display = "block";
  $("master").value = "";
}

async function addEntry() {
  const t = $("title").value.trim();
  const u = $("user").value.trim();
  const p = $("pass").value.trim();
  if (!t || !u || !p) return flash("All fields required");
  VAULT.push({ title: t, user: u, pass: p, id: crypto.randomUUID() });
  $("title").value = $("user").value = $("pass").value = "";
  await persist();
  render();
}

function delEntry(id) {
  VAULT = VAULT.filter(x => x.id !== id);
  persist();
  render();
}

function render() {
  const list = $("list");
  list.innerHTML = "";
  VAULT.forEach(en => {
    const div = document.createElement("div");
    div.className = "entry";
    div.innerHTML = `
      <div>
        <strong>${esc(en.title)}</strong><br />
        <span style="opacity:.7">User:</span> ${esc(en.user)} |
        <span style="opacity:.7">Pass:</span> ${esc(en.pass)}
      </div>
      <button onclick="delEntry('${en.id}')">Delete</button>
    `;
    list.appendChild(div);
  });
}

async function getSalt() {
  let s = localStorage.getItem("salt");
  if (!s) {
    const arr = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
    s = btoa(String.fromCharCode(...arr));
    localStorage.setItem("salt", s);
  }
  const binary = atob(s);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

async function persist() {
  const plain = JSON.stringify(VAULT);
  const payload = await encrypt(plain, KEY);
  localStorage.setItem("vault", JSON.stringify(payload));
}

async function downloadBackup() {
  const payload = localStorage.getItem("vault");
  const blob = new Blob([payload], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "vault-backup-" + new Date().toISOString().slice(0, 10) + ".json";
  a.click();
}

async function uploadBackup(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const payload = JSON.parse(text);
    await decrypt(payload, KEY);
    localStorage.setItem("vault", text);
    location.reload();
  } catch (e) {
    flash("Backup file invalid or wrong key");
  }
}

function flash(msg) {
  const e = $("error");
  e.textContent = msg;
  setTimeout(() => e.textContent = "", 2500);
}

function esc(str) {
  return str.replace(/[&<>"']/g, s => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[s]);
}