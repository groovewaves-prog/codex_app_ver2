const fileInput = document.getElementById("file-input");
const fileList = document.getElementById("file-list");
const reviewButton = document.getElementById("review-button");
const summary = document.getElementById("summary");
const issues = document.getElementById("issues");
const warnings = document.getElementById("warnings");
const documents = document.getElementById("documents");
const securityCard = document.getElementById("security-card");
const issueTemplate = document.getElementById("issue-template");

const selectedFiles = [];

fileInput.addEventListener("change", async (event) => {
  selectedFiles.length = 0;
  fileList.innerHTML = "";

  for (const file of event.target.files) {
    const content = await readFile(file);
    selectedFiles.push({
      name: file.name,
      content,
      contentType: file.type || "text/plain",
    });
    renderFileChip(file.name, file.size);
  }
});

reviewButton.addEventListener("click", async () => {
  if (selectedFiles.length === 0) {
    window.alert("Select at least one file.");
    return;
  }

  reviewButton.disabled = true;
  reviewButton.textContent = "Review in progress...";
  summary.className = "summary muted";
  summary.textContent = "Running sanitization and review.";
  issues.innerHTML = "";

  try {
    const response = await fetch("/api/review", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ documents: selectedFiles }),
    });
    const payload = await response.json();

    if (!response.ok) {
      throw new Error(payload.error || "Review failed.");
    }

    renderReview(payload);
  } catch (error) {
    summary.className = "summary error";
    summary.textContent = error.message;
  } finally {
    reviewButton.disabled = false;
    reviewButton.textContent = "Sanitize and review";
  }
});

function renderFileChip(name, size) {
  const chip = document.createElement("div");
  chip.className = "file-chip";
  chip.textContent = `${name} (${Math.ceil(size / 1024)} KB)`;
  fileList.appendChild(chip);
}

function renderReview(payload) {
  summary.className = "summary";
  summary.textContent = `${payload.review.summary} Provider: ${payload.review.provider}`;

  issues.innerHTML = "";
  for (const item of payload.review.issues) {
    const node = issueTemplate.content.cloneNode(true);
    node.querySelector(".badge").textContent = item.severity.toUpperCase();
    node.querySelector(".badge").classList.add(`severity-${item.severity}`);
    node.querySelector(".source").textContent = item.source_document;
    node.querySelector("h3").textContent = item.title;
    node.querySelector(".details").textContent = item.details;
    node.querySelector(".recommendation").textContent = `Recommendation: ${item.recommendation}`;
    issues.appendChild(node);
  }

  warnings.className = "warnings";
  warnings.innerHTML = "";
  const warningItems = payload.warnings.length ? payload.warnings : ["No warnings."];
  for (const item of warningItems) {
    const li = document.createElement("li");
    li.textContent = item;
    warnings.appendChild(li);
  }

  documents.className = "documents";
  documents.innerHTML = "";
  for (const doc of payload.documents) {
    const article = document.createElement("article");
    article.className = "document-card";
    article.innerHTML = `
      <h3>${escapeHtml(doc.name)}</h3>
      <p class="doc-findings">${(doc.findings || []).join(" ") || "Sensitive values were sanitized locally."}</p>
      <div class="doc-preview">
        <section>
          <h4>Original excerpt</h4>
          <pre>${escapeHtml(doc.original_excerpt)}</pre>
        </section>
        <section>
          <h4>Sanitized excerpt</h4>
          <pre>${escapeHtml(doc.sanitized_excerpt)}</pre>
        </section>
      </div>
      <p class="doc-meta">Replacement count: ${doc.replacements.length}</p>
    `;
    documents.appendChild(article);
  }

  securityCard.className = "security-card";
  securityCard.innerHTML = `
    <strong>Outbound protection:</strong> ${escapeHtml(payload.security.message)}<br />
    <strong>Total replacements:</strong> ${payload.security.replacements}
  `;
}

async function readFile(file) {
  if (file.name.toLowerCase().endsWith(".docx")) {
    const binary = await readArrayBuffer(file);
    return toLatin1(binary);
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error(`Failed to read ${file.name}.`));
    reader.readAsText(file);
  });
}

function readArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error(`Failed to read ${file.name}.`));
    reader.readAsArrayBuffer(file);
  });
}

function toLatin1(buffer) {
  const bytes = new Uint8Array(buffer);
  let result = "";
  for (const byte of bytes) {
    result += String.fromCharCode(byte);
  }
  return result;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
