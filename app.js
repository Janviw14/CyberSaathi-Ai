const translations = {
  en: {language:"Language",nav_message:"Message checker",nav_url:"URL checker",nav_upi:"UPI QR decoder",nav_report:"Report financial cyber fraud"},
  hi: {language:"भाषा",nav_message:"मैसेज जांचें",nav_url:"URL जांचें",nav_upi:"UPI QR डिकोडर",nav_report:"वित्तीय साइबर धोखाधड़ी की रिपोर्ट करें"},
  mr: {language:"भाषा",nav_message:"संदेश तपासा",nav_url:"URL तपासा",nav_upi:"UPI QR डिकोडर",nav_report:"आर्थिक सायबर फसवणुकीची तक्रार"}
};
const langSelect = document.getElementById("languageSelect");
if (langSelect) {
  const saved = localStorage.getItem("cs-language") || "en";
  langSelect.value = saved;
  applyLanguage(saved);
  langSelect.addEventListener("change", () => {
    localStorage.setItem("cs-language", langSelect.value);
    applyLanguage(langSelect.value);
  });
}
function applyLanguage(lang) {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.dataset.i18n;
    if (translations[lang] && translations[lang][key]) el.textContent = translations[lang][key];
  });
}
function showResult(target, data) {
  target.replaceChildren();
  target.classList.remove("hidden");
  if (data.error) {
    const p = document.createElement("p"); p.className = "error-text"; p.textContent = data.error; target.append(p); return;
  }
  const risk = document.createElement("div");
  const riskName = data.risk || (data.valid ? "Decoded" : "Unable to decode");
  risk.className = "risk-heading risk-" + String(riskName).toLowerCase();
  risk.textContent = "Result: " + riskName + (data.score !== undefined ? " · heuristic score " + data.score : "");
  target.append(risk);
  if (data.host) addDetail(target, "Domain checked", data.host);
  if (data.payee_name || data.upi_id || data.amount) {
    addDetail(target, "Payee name", data.payee_name || "Not included");
    addDetail(target, "UPI ID", data.upi_id || "Not included");
    addDetail(target, "Amount", data.amount ? data.currency + " " + data.amount : "Not specified");
    if (data.note) addDetail(target, "Payment note", data.note);
  }
  if (Array.isArray(data.signals) && data.signals.length) {
    const h = document.createElement("h3"); h.textContent = data.valid ? "Decoded information" : "What we noticed"; target.append(h);
    const ul = document.createElement("ul"); ul.className = "result-list";
    data.signals.forEach(signal => {
      const li = document.createElement("li");
      li.textContent = typeof signal === "string" ? signal : `${signal.category}: ${signal.explanation}`;
      ul.append(li);
    });
    target.append(ul);
  } else if (data.risk) {
    const p = document.createElement("p"); p.textContent = "No matching warning pattern was detected. This is not proof that the content is safe."; target.append(p);
  }
  if (data.guidance || data.warning) addDetail(target, "Recommended action", data.guidance || data.warning);
  if (data.disclaimer) { const p = document.createElement("p"); p.className = "disclaimer"; p.textContent = data.disclaimer; target.append(p); }
}
function addDetail(parent, label, value) {
  const p = document.createElement("p"); p.className = "result-detail";
  const strong = document.createElement("strong"); strong.textContent = label + ": ";
  p.append(strong, document.createTextNode(value)); parent.append(p);
}
async function postJSON(url, payload) {
  const response = await fetch(url, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Request failed. Please try again.");
  return data;
}
const msg = document.getElementById("messageInput");
if (msg) {
  const count = document.getElementById("messageCount");
  msg.addEventListener("input", () => count.textContent = `${msg.value.length} / 3000`);
  document.getElementById("checkMessage").addEventListener("click", async () => {
    const target = document.getElementById("messageResult");
    try { showResult(target, await postJSON("/api/message", {text:msg.value, language:langSelect?.value || "en"})); }
    catch(e) { showResult(target, {error:e.message}); }
  });
  document.getElementById("clearMessage").addEventListener("click", () => {
    msg.value = ""; count.textContent = "0 / 3000"; document.getElementById("messageResult").classList.add("hidden");
  });
}
const urlInput = document.getElementById("urlInput");
if (urlInput) {
  document.getElementById("checkUrl").addEventListener("click", async () => {
    const target = document.getElementById("urlResult");
    try { showResult(target, await postJSON("/api/url", {url:urlInput.value})); }
    catch(e) { showResult(target, {error:e.message}); }
  });
  document.getElementById("clearUrl").addEventListener("click", () => {
    urlInput.value = ""; document.getElementById("urlResult").classList.add("hidden");
  });
}
const upiInput = document.getElementById("upiInput");
if (upiInput) {
  document.getElementById("decodeUpi").addEventListener("click", async () => {
    try { showResult(document.getElementById("upiResult"), await postJSON("/api/upi", {uri:upiInput.value})); }
    catch(e) { showResult(document.getElementById("upiResult"), {error:e.message}); }
  });
  const video = document.getElementById("qrVideo"), canvas = document.getElementById("qrCanvas");
  const start = document.getElementById("startCamera"), stop = document.getElementById("stopCamera");
  let stream = null, scanning = false, detector = null;
  async function scanFrame() {
    if (!scanning || !video.videoWidth) { if (scanning) requestAnimationFrame(scanFrame); return; }
    try {
      const codes = await detector.detect(video);
      if (codes.length) {
        upiInput.value = codes[0].rawValue;
        document.getElementById("qrStatus").textContent = "QR detected. Select Decode payment details to review it.";
        stopCamera.click(); return;
      }
    } catch (_) { document.getElementById("qrStatus").textContent = "Could not read this QR. Try uploading a clear image or paste its content."; }
    requestAnimationFrame(scanFrame);
  }
  async function decodeImage(file) {
    if (!("BarcodeDetector" in window)) throw new Error("This browser does not support QR image detection. Try a supported Chromium-based browser or paste the UPI URI.");
    const detector = new BarcodeDetector({formats:["qr_code"]});
    const bitmap = await createImageBitmap(file);
    const codes = await detector.detect(bitmap);
    bitmap.close();
    if (!codes.length) throw new Error("No readable QR code found in this image.");
    upiInput.value = codes[0].rawValue;
    document.getElementById("qrStatus").textContent = "QR decoded from image. Select Decode payment details to review it.";
  }
  start.addEventListener("click", async () => {
    try {
      if (!("BarcodeDetector" in window)) throw new Error("Your browser does not support BarcodeDetector. Try uploading an image in a supported browser or paste the UPI URI.");
      detector = new BarcodeDetector({formats:["qr_code"]});
      stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:"environment"}});
      video.srcObject = stream; await video.play(); video.classList.remove("hidden");
      scanning = true; start.disabled = true; stop.disabled = false; scanFrame();
    } catch(e) { document.getElementById("qrStatus").textContent = e.message; }
  });
  stop.addEventListener("click", () => {
    scanning = false; if (stream) stream.getTracks().forEach(t => t.stop());
    stream = null; video.srcObject = null; video.classList.add("hidden");
    start.disabled = false; stop.disabled = true;
  });
  document.getElementById("qrFile").addEventListener("change", async e => {
    const file = e.target.files[0]; if (!file) return;
    try { await decodeImage(file); } catch(err) { document.getElementById("qrStatus").textContent = err.message; }
    e.target.value = "";
  });
  window.addEventListener("pagehide", () => { if (stream) stream.getTracks().forEach(t => t.stop()); });
}
