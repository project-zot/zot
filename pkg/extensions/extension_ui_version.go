//go:build search && ui

package extensions

import "bytes"

const (
	uiVersionInfoScriptPath = "/assets/zot-version-info.js"
	uiVersionInfoJSONPath   = "/assets/zot-version.json"
	uiVersionInfoScriptTag  = `<script type="module" crossorigin src="` + uiVersionInfoScriptPath + `"></script>`
	uiVersionInfoScript     = `
const versionInfoID = "zot-version-info";
const versionEndpoint = "/assets/zot-version.json";

const copyText = async (text) => {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);

    return;
  }

  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.setAttribute("readonly", "");
  textArea.style.position = "fixed";
  textArea.style.opacity = "0";
  document.body.appendChild(textArea);
  textArea.select();
  document.execCommand("copy");
  textArea.remove();
};

const displayValue = (value, fallback) => {
  if (typeof value !== "string" || value.trim() === "") {
    return fallback;
  }

  return value.trim();
};

const renderVersionInfo = (versionInfo) => {
  if (document.getElementById(versionInfoID)) {
    return;
  }

  const releaseTag = displayValue(versionInfo.releaseTag, "unknown");
  const commit = displayValue(versionInfo.commit, "unknown");
  const binaryType = displayValue(versionInfo.binaryType, "");
  const copyValue = "zot " + releaseTag + " commit " + commit;
  const visibleValue = binaryType === ""
    ? "zot " + releaseTag + " | commit " + commit
    : "zot " + releaseTag + " | " + binaryType + " | commit " + commit;

  const style = document.createElement("style");
  style.textContent = [
    "#" + versionInfoID + " {",
    "  position: fixed;",
    "  right: 16px;",
    "  bottom: 16px;",
    "  z-index: 1200;",
    "  display: flex;",
    "  max-width: calc(100vw - 32px);",
    "  align-items: center;",
    "  gap: 8px;",
    "  box-sizing: border-box;",
    "  padding: 6px 8px 6px 10px;",
    "  border: 1px solid rgba(31, 41, 55, 0.18);",
    "  border-radius: 4px;",
    "  background: rgba(255, 255, 255, 0.94);",
    "  color: #1f2937;",
    "  box-shadow: 0 4px 12px rgba(31, 41, 55, 0.16);",
    "  font-family: Roboto, Arial, sans-serif;",
    "  font-size: 12px;",
    "  line-height: 16px;",
    "}",
    "#" + versionInfoID + " span {",
    "  overflow: hidden;",
    "  text-overflow: ellipsis;",
    "  white-space: nowrap;",
    "  user-select: text;",
    "}",
    "#" + versionInfoID + " button {",
    "  flex: 0 0 auto;",
    "  min-width: 44px;",
    "  height: 24px;",
    "  border: 1px solid rgba(31, 41, 55, 0.28);",
    "  border-radius: 4px;",
    "  background: #ffffff;",
    "  color: #1f2937;",
    "  cursor: pointer;",
    "  font: inherit;",
    "}",
    "#" + versionInfoID + " button:focus-visible {",
    "  outline: 2px solid #1d4ed8;",
    "  outline-offset: 2px;",
    "}",
  ].join("\n");
  document.head.appendChild(style);

  const container = document.createElement("aside");
  container.id = versionInfoID;
  container.setAttribute("aria-label", "zot version information");

  const label = document.createElement("span");
  label.textContent = visibleValue;
  label.title = visibleValue;

  const copyButton = document.createElement("button");
  copyButton.type = "button";
  copyButton.textContent = "Copy";
  copyButton.title = "Copy zot version information";
  copyButton.addEventListener("click", async () => {
    try {
      await copyText(copyValue);
      copyButton.textContent = "Copied";
      window.setTimeout(() => {
        copyButton.textContent = "Copy";
      }, 1200);
    } catch (error) {
      copyButton.textContent = "Copy";
    }
  });

  container.appendChild(label);
  container.appendChild(copyButton);
  document.body.appendChild(container);
};

const loadVersionInfo = async () => {
  const response = await fetch(versionEndpoint, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });

  if (!response.ok) {
    return;
  }

  renderVersionInfo(await response.json());
};

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    loadVersionInfo().catch(() => {});
  }, { once: true });
} else {
  loadVersionInfo().catch(() => {});
}
`
)

type uiVersionInfo struct {
	Commit          string `json:"commit"`
	ReleaseTag      string `json:"releaseTag"`
	BinaryType      string `json:"binaryType"`
	GoVersion       string `json:"goVersion"`
	DistSpecVersion string `json:"distSpecVersion"`
}

func injectVersionInfoScript(indexHTML []byte) []byte {
	if bytes.Contains(indexHTML, []byte(uiVersionInfoScriptPath)) {
		return indexHTML
	}

	return bytes.Replace(indexHTML, []byte("</head>"), []byte("    "+uiVersionInfoScriptTag+"\n  </head>"), 1)
}
