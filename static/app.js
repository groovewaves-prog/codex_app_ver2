const fileInput = document.getElementById("file-input");
const fileList = document.getElementById("file-list");
const reviewButton = document.getElementById("review-button");
const summary = document.getElementById("summary");
const issues = document.getElementById("issues");
const warnings = document.getElementById("warnings");
const documents = document.getElementById("documents");
const securityCard = document.getElementById("security-card");
const issueTemplate = document.getElementById("issue-template");
const documentProfile = document.getElementById("document-profile");
const binaryExtensions = new Set([
  ".docx",
  ".xlsx",
  ".pptx",
  ".png",
  ".jpg",
  ".jpeg",
  ".bmp",
  ".gif",
  ".tif",
  ".tiff",
  ".webp",
]);

const selectedFiles = [];

fileInput.addEventListener("change", async (event) => {
  selectedFiles.length = 0;
  fileList.innerHTML = "";

  for (const file of event.target.files) {
    const payload = await readFile(file);
    selectedFiles.push({
      name: file.name,
      content: payload.content,
      contentType: file.type || "text/plain",
      transferEncoding: payload.transferEncoding,
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
      body: JSON.stringify({
        documents: selectedFiles,
        documentProfile: documentProfile?.value || "",
      }),
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
  summary.textContent = `${payload.review.summary} Provider: ${payload.review.provider} Rubric: ${payload.review.rubric_name || "-"} Classification: ${payload.review.document_profile || "-"} (${payload.review.classification_confidence || "unknown"})`;

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
      <p class="doc-meta">Replacement count: ${doc.replacements.length} | Estimated input tokens: ${doc.estimated_input_tokens} | Outbound risk: ${escapeHtml(doc.outbound_risk)} | Local sensitivity: ${escapeHtml(doc.local_sensitivity_decision || "unknown")}</p>
    `;
    documents.appendChild(article);
  }

  securityCard.className = "security-card";
  securityCard.innerHTML = `
    <strong>Outbound protection:</strong> ${escapeHtml(payload.security.message)}<br />
    <strong>Total replacements:</strong> ${payload.security.replacements}<br />
    <strong>Estimated input tokens:</strong> ${payload.security.estimated_input_tokens}<br />
    <strong>Highest outbound risk:</strong> ${escapeHtml(payload.security.max_outbound_risk)}<br />
    <strong>Local sensitivity provider:</strong> ${escapeHtml(payload.security.local_sensitivity_provider || "-")}<br />
    <strong>Classification reason:</strong> ${escapeHtml(payload.review.classification_reason || "-")}
  `;
}

async function readFile(file) {
  if (isBinaryFile(file)) {
    const binary = await readArrayBuffer(file);
    return {
      content: toBase64(binary),
      transferEncoding: "base64",
    };
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () =>
      resolve({
        content: reader.result,
        transferEncoding: "text",
      });
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

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

function isBinaryFile(file) {
  const lower = file.name.toLowerCase();
  for (const extension of binaryExtensions) {
    if (lower.endsWith(extension)) {
      return true;
    }
  }
  return false;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
