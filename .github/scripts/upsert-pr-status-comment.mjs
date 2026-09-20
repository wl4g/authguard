#!/usr/bin/env node

const repository = process.env.GITHUB_REPOSITORY;
const pullRequest = process.env.AUTHGUARD_PR_NUMBER;
const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
const kind = process.env.AUTHGUARD_COMMENT_KIND;
const phase = process.env.AUTHGUARD_COMMENT_PHASE;
const runUrl = process.env.AUTHGUARD_RUN_URL;
const dirtyTag = process.env.AUTHGUARD_DIRTY_TAG;
const dirtyChartVersion = process.env.AUTHGUARD_DIRTY_CHART_VERSION;
const buildResult = process.env.AUTHGUARD_BUILD_RESULT;
const kubernetesE2eResult = process.env.AUTHGUARD_E2E_KUBERNETES_RESULT;
const kubernetesE2eSummary = process.env.AUTHGUARD_E2E_KUBERNETES_SUMMARY_BASE64;
const dockerE2eResult = process.env.AUTHGUARD_E2E_DOCKER_RESULT;
const dockerE2eSummary = process.env.AUTHGUARD_E2E_DOCKER_SUMMARY_BASE64;
const releaseResult = process.env.AUTHGUARD_RELEASE_RESULT;
const prepareResult = process.env.AUTHGUARD_PREPARE_RESULT;
const releaseVersion = process.env.AUTHGUARD_RELEASE_VERSION;
const releaseTag = process.env.AUTHGUARD_RELEASE_TAG;
const shouldRelease = process.env.AUTHGUARD_SHOULD_RELEASE;

if (!repository || !pullRequest || !token || !kind || !phase || !runUrl) {
  throw new Error("Missing AuthGuard PR status comment context.");
}

const [owner, repo] = repository.split("/", 2);
const marker = `<!-- authguard-${kind}-status -->`;
const apiBase = `https://api.github.com/repos/${owner}/${repo}/issues/${pullRequest}/comments`;

const resultIcon = (result) => {
  if (result === "success") return "✅";
  if (result === "skipped") return "⏭️";
  if (result === "failure" || result === "cancelled" || result === "timed_out") return "❌";
  return "⏳";
};

const displayResult = (result) => result || "pending";

const decodeSummary = (encoded) => {
  if (!encoded) return "E2E summary was not generated; see the evidence artifact.";
  const summary = Buffer.from(encoded, "base64").toString("utf8").trim();
  if (!summary) return "E2E summary was empty; see the evidence artifact.";
  if (summary.length > 20_000) {
    return `${summary.slice(0, 20_000)}\n\n[Summary truncated; see the evidence artifact for the complete report.]`;
  }
  return summary;
};

const appendE2eSummary = (details, name, result, summary, artifactUrl) => {
  details.push(`- ${name}: ${resultIcon(result)} ${displayResult(result)}`);
  if (result === "skipped") {
    details.push(`  - ${name} did not start because the build stage did not succeed.`);
    return;
  }
  details.push(`  - Evidence: [reports and screenshots](${artifactUrl})`);
  details.push("", `### ${name} summary`, "", "```text", decodeSummary(summary).replaceAll("```", "``\\`"), "```");
};

const renderCi = () => {
  const artifactUrl = `${runUrl}#artifacts`;
  const details = [
    marker,
    "## AuthGuard PR CI",
    "",
    `- Run: [Actions log](${runUrl})`,
  ];

  if (phase === "started") {
    details.push("- Status: ⏳ CI started: building dirty images, then running Kubernetes and Docker Compose E2E in parallel.");
    return details.join("\n");
  }

  details.push(`- Build / UT / IT: ${resultIcon(buildResult)} ${displayResult(buildResult)}`);
  if (buildResult === "success" && dirtyTag) {
    details.push("", "### PR artifacts", "", `- Runtime: \`ghcr.io/wl4g/authguard:${dirtyTag}\``, `- Web: \`ghcr.io/wl4g/authguard-web:${dirtyTag}\``);
    if (dirtyChartVersion) {
      details.push(`- Helm chart: [\`authguard-${dirtyChartVersion}.tgz\`](${artifactUrl})`);
    }
  }

  if (phase === "build") {
    details.push("", buildResult === "success"
      ? "- Status: ⏳ Dirty images and the chart package are ready; Kubernetes and Docker Compose E2E are running in parallel."
      : "- Status: ❌ Build failed; E2E jobs were not started.");
    return details.join("\n");
  }

  appendE2eSummary(
    details,
    "Full customer-growth Kubernetes E2E",
    kubernetesE2eResult,
    kubernetesE2eSummary,
    artifactUrl,
  );
  appendE2eSummary(
    details,
    "Full customer-growth Docker Compose E2E",
    dockerE2eResult,
    dockerE2eSummary,
    artifactUrl,
  );
  const passed = buildResult === "success"
    && kubernetesE2eResult === "success"
    && dockerE2eResult === "success";
  details.push("", passed
    ? "**CI completed successfully.**"
    : kubernetesE2eResult === "skipped" && dockerE2eResult === "skipped"
      ? `**CI failed.** Review the [Actions log](${runUrl}).`
      : `**CI failed.** Review the [Actions log](${runUrl}) and E2E evidence.`);
  return details.join("\n");
};

const renderRelease = () => {
  const details = [
    marker,
    "## AuthGuard Release",
    "",
    `- Run: [Actions log](${runUrl})`,
  ];

  if (phase === "started") {
    details.push("- Status: ⏳ Release started; evaluating the merged PR title and preparing immutable artifacts.");
    return details.join("\n");
  }

  if (prepareResult && prepareResult !== "success") {
    details.push("", `**Release preparation failed.** Review the [Actions log](${runUrl}).`);
    return details.join("\n");
  }

  if (shouldRelease !== "true") {
    details.push("- Status: ⏭️ No release. Only merged PR titles beginning with `refactor:`, `feat:`, or `fix:` publish artifacts.");
    return details.join("\n");
  }

  details.push(`- Version: \`${releaseVersion}\` (${releaseTag})`);
  if (releaseResult === "success") {
    details.push(
      "",
      "### Official artifacts",
      "",
      `- Runtime: \`ghcr.io/wl4g/authguard:${releaseVersion}\``,
      `- Web: \`ghcr.io/wl4g/authguard-web:${releaseVersion}\``,
      `- Helm chart: \`oci://ghcr.io/wl4g/charts/authguard --version ${releaseVersion}\``,
      `- Release: [${releaseTag}](https://github.com/${repository}/releases/tag/${releaseTag})`,
      "",
      "**Release completed successfully.**",
    );
  } else {
    details.push("", `**Release failed.** Review the [Actions log](${runUrl}).`);
  }
  return details.join("\n");
};

const body = kind === "ci" ? renderCi() : renderRelease();
if (process.env.AUTHGUARD_COMMENT_DRY_RUN === "true") {
  console.log(body);
  process.exit(0);
}

const headers = {
  Accept: "application/vnd.github+json",
  Authorization: `Bearer ${token}`,
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type": "application/json",
};

const request = async (url, options = {}) => {
  const response = await fetch(url, { ...options, headers: { ...headers, ...options.headers } });
  if (!response.ok) {
    throw new Error(`GitHub API ${options.method || "GET"} ${url} failed: ${response.status} ${await response.text()}`);
  }
  return response.status === 204 ? undefined : response.json();
};

const comments = await request(`${apiBase}?per_page=100`);
const existing = comments.find(
  (comment) => comment.user?.login === "github-actions[bot]" && comment.body?.includes(marker),
);
if (existing) {
  await request(
    `https://api.github.com/repos/${owner}/${repo}/issues/comments/${existing.id}`,
    { method: "PATCH", body: JSON.stringify({ body }) },
  );
} else {
  await request(apiBase, { method: "POST", body: JSON.stringify({ body }) });
}
