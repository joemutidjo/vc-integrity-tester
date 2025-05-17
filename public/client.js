document
.getElementById("vcForm")
.addEventListener("submit", async function (e) {
  e.preventDefault();

  const fileInput = document.getElementById("vc");
  const resultsSection = document.getElementById("results");
  const summaryList = document.getElementById("summaryList");
  const structureDetails = document.getElementById("structureDetails");
  const jwtDetails = document.getElementById("jwtDetails");
  const didOutput = document.getElementById("didOutput");
  const tamperDiffDiv = document.getElementById("tamperDiff");

  summaryList.innerHTML = "";
  structureDetails.innerHTML = "";
  jwtDetails.innerHTML = "";
  didOutput.textContent = "";
  tamperDiffDiv.innerHTML = "";
  resultsSection.style.display = "none";

  if (!fileInput.files.length) {
    alert("Please select a VC file to upload.");
    return;
  }

  const formData = new FormData();
  formData.append("vc", fileInput.files[0]);

  try {
    const response = await fetch("/verify", {
      method: "POST",
      body: formData
    });

    const data = await response.json();
    resultsSection.style.display = "block";

    const addSummaryItem = (label, passed) => {
      const li = document.createElement("li");
      li.innerHTML = `${passed ? "✅" : "❌"} <strong>${label}</strong>`;
      summaryList.appendChild(li);
    };

    if (data.validStructure) {
      addSummaryItem("VC Structure Valid", true);
      structureDetails.innerHTML = `<p>Structure looks good.</p>`;
    } else {
      addSummaryItem("VC Structure Valid", false);
      structureDetails.innerHTML = `
        <p><strong>Error:</strong> ${data.error || "Validation failed."}</p>
        <pre>${JSON.stringify(data.structureIssues || {}, null, 2)}</pre>`;
    }

    if (data.jwtVerified) {
      addSummaryItem("JWS Signature Verified", true);
      jwtDetails.innerHTML = `
        ${data.jwtHeader ? `<h4>JWT Header</h4><pre>${JSON.stringify(data.jwtHeader, null, 2)}</pre>` : ""}
        ${data.jwtPayload ? `<h4>JWT Payload</h4><pre>${JSON.stringify(data.jwtPayload, null, 2)}</pre>` : ""}`;
    } else {
      addSummaryItem("JWS Signature Verified", false);
      jwtDetails.innerHTML = `<p><strong>Signature Verification Error:</strong> ${data.jwtError || "Unknown issue."}</p>`;
    }

    if (data.didResolution) {
      const failed = data.didResolution.error;
      addSummaryItem("DID Resolution", !failed);
      didOutput.textContent = JSON.stringify(data.didResolution, null, 2);
    } else {
      addSummaryItem("DID Resolution", false);
      didOutput.textContent = "No DID information available.";
    }

    // ✅ Credential hash check summary
    if (data.credentialHashCheck !== null && data.credentialHashCheck !== undefined) {
      addSummaryItem("Credential Hash Matches", data.credentialHashCheck);
    }

    // ✅ Optional: show embedded and calculated hash values
    if (data.embeddedHash && data.calculatedHash) {
      jwtDetails.innerHTML += `
        <h4>Hash Verification</h4>
        <p><strong>Embedded Hash:</strong> ${data.embeddedHash}</p>
        <p><strong>Calculated Hash:</strong> ${data.calculatedHash}</p>
      `;
    }

    if (
      data.tamperDiff &&
      (Object.keys(data.tamperDiff.added).length ||
        Object.keys(data.tamperDiff.changed).length ||
        Object.keys(data.tamperDiff.removed).length)
    ) {
      tamperDiffDiv.innerHTML = `
        <h4 style="color: darkorange">⚠️ Tampering Detected</h4>
        <ul>
          ${
            Object.keys(data.tamperDiff.added).length
              ? `<li><strong>Fields added:</strong> ${Object.keys(data.tamperDiff.added).join(", ")}</li>`
              : ""
          }
          ${
            Object.keys(data.tamperDiff.changed).length
              ? `<li><strong>Fields changed:</strong> ${Object.keys(data.tamperDiff.changed).join(", ")}</li>`
              : ""
          }
          ${
            Object.keys(data.tamperDiff.removed).length
              ? `<li><strong>Fields removed:</strong> ${Object.keys(data.tamperDiff.removed).join(", ")}</li>`
              : ""
          }
        </ul>
        <pre>${JSON.stringify(data.tamperDiff, null, 2)}</pre>
      `;
    }
  } catch (err) {
    resultsSection.style.display = "block";
    summaryList.innerHTML = `<li style="color:red"><strong>Error:</strong> ${err.message}</li>`;
  }
});
