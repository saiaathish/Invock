import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";
import { startApi } from "../src/api/server.js";
import { InvockStore } from "../src/storage/store.js";

type CheckStatus = "PASS" | "FAIL" | "NOT_PROVEN" | "UNSUPPORTED";
interface Check { readonly status: CheckStatus; readonly evidence: string; }
interface AccessibilityReport {
  readonly command: "accessibility-certify";
  readonly status: "PASS" | "NOT_CERTIFIED" | "UNSUPPORTED";
  readonly environment: {
    readonly browserPath: "regular-playwright";
    readonly browserPlugin: "unavailable";
    readonly node: string;
    readonly platform: string;
    readonly playwright: string;
    readonly chromiumExecutable: string;
    readonly viewport: { readonly desktop: string; readonly mobile: string };
  };
  readonly checks: Record<string, Check>;
  readonly interaction: { readonly executed: boolean; readonly path: string; readonly stateChange: string; readonly apiResponses: Record<string, number> };
  readonly console: { readonly errors: string[]; readonly warnings: string[]; readonly pageErrors: string[]; readonly requestFailures: string[] };
  readonly screenshots: string[];
  readonly artifactPath: string;
  readonly blockers: string[];
}

const require = createRequire(import.meta.url);
const packageVersion = (): string => {
  try { return (require("playwright/package.json") as { version: string }).version; } catch { return "unknown"; }
};
const check = (status: CheckStatus, evidence: string): Check => ({ status, evidence });

function contrastRatio(foreground: string, background: string): number {
  const rgb = (value: string): [number, number, number] => {
    const match = value.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/u);
    if (!match) throw new Error(`Cannot parse color: ${value}`);
    return [Number(match[1]), Number(match[2]), Number(match[3])];
  };
  const luminance = (value: string): number => rgb(value).map(channel => channel / 255).map(channel => channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index]!, 0);
  const light = luminance(foreground); const dark = luminance(background);
  return (Math.max(light, dark) + 0.05) / (Math.min(light, dark) + 0.05);
}

function writeOutput(report: AccessibilityReport, jsonOnly: boolean): void {
  writeFileSync(report.artifactPath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  if (jsonOnly) console.log(JSON.stringify(report, null, 2));
  else console.log(`INVOCK ACCESSIBILITY CERTIFICATION\nSTATUS: ${report.status}\nENVIRONMENT: ${report.environment.browserPath}; Browser plugin=${report.environment.browserPlugin}; Chromium=${report.environment.chromiumExecutable}; viewport=${report.environment.viewport.desktop} + ${report.environment.viewport.mobile}\nCHECKS:\n${Object.entries(report.checks).map(([name, item]) => `- ${name}: ${item.status} — ${item.evidence}`).join("\n")}\nINTERACTION: ${report.interaction.path}; ${report.interaction.stateChange}\nCONSOLE: errors=${report.console.errors.length}, warnings=${report.console.warnings.length}, pageErrors=${report.console.pageErrors.length}, requestFailures=${report.console.requestFailures.length}\nARTIFACT: ${report.artifactPath}\nSCREENSHOTS:\n${report.screenshots.map(item => `- ${item}`).join("\n")}\nBLOCKERS:\n${report.blockers.length > 0 ? report.blockers.map(item => `- ${item}`).join("\n") : "- none"}`);
}

async function main(): Promise<number> {
  const jsonOnly = process.argv.includes("--json");
  const artifactDirectory = mkdtempSync(join(tmpdir(), "invock-accessibility-"));
  mkdirSync(artifactDirectory, { recursive: true, mode: 0o700 });
  const artifactPath = join(artifactDirectory, "accessibility-report.json");
  const screenshots: string[] = [];
  const checks: Record<string, Check> = {};
  const blockers: string[] = [];
  const consoleErrors: string[] = [];
  const consoleWarnings: string[] = [];
  const pageErrors: string[] = [];
  const requestFailures: string[] = [];
  const apiResponses: Record<string, number> = {};
  const store = new InvockStore(":memory:");
  const api = await startApi(store, { token: "accessibility-certification-token" });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  const baseReport = {
    command: "accessibility-certify" as const,
    environment: {
      browserPath: "regular-playwright" as const,
      browserPlugin: "unavailable" as const,
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
      playwright: packageVersion(),
      chromiumExecutable: chromium.executablePath(),
      viewport: { desktop: "1280x900", mobile: "390x844" },
    },
    checks,
    interaction: { executed: false, path: "", stateChange: "", apiResponses },
    console: { errors: consoleErrors, warnings: consoleWarnings, pageErrors, requestFailures },
    screenshots,
    artifactPath,
    blockers,
  };
  try {
    if (!existsSync(chromium.executablePath())) {
      checks.browserRuntime = check("UNSUPPORTED", `Chromium executable was not found at ${chromium.executablePath()}`);
      blockers.push("REAL_BROWSER_RUNTIME_UNAVAILABLE");
      writeOutput({ ...baseReport, status: "UNSUPPORTED" }, jsonOnly); return 2;
    }
    try { browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"] }); }
    catch (error) {
      checks.browserRuntime = check("UNSUPPORTED", `Playwright could not launch Chromium: ${error instanceof Error ? error.message : String(error)}`);
      blockers.push("REAL_BROWSER_LAUNCH_FAILED");
      writeOutput({ ...baseReport, status: "UNSUPPORTED" }, jsonOnly); return 2;
    }
    checks.browserRuntime = check("PASS", `Launched Chromium ${browser.version()} through Playwright ${packageVersion()}`);
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    const page = await context.newPage();
    page.on("console", message => { if (message.type() === "error") consoleErrors.push(message.text()); if (message.type() === "warning") consoleWarnings.push(message.text()); });
    page.on("pageerror", error => pageErrors.push(error.message));
    page.on("requestfailed", request => requestFailures.push(`${request.method()} ${request.url()} :: ${request.failure()?.errorText ?? "unknown"}`));

    const url = `${api.url}/`;
    const response = await page.goto(url, { waitUntil: "networkidle" });
    const initialScreenshot = join(artifactDirectory, "desktop-initial.png");
    await page.screenshot({ path: initialScreenshot, fullPage: true }); screenshots.push(initialScreenshot);
    checks.pageIdentity = response?.status() === 200 && page.url() === url && await page.title() === "Invock"
      ? check("PASS", `HTTP ${response.status()}, URL ${page.url()}, title Invock`)
      : check("FAIL", `HTTP ${response?.status() ?? "no response"}, URL ${page.url()}, title ${await page.title()}`);
    const initialDom = await page.locator("body").innerText();
    checks.nonBlank = /Invock.*local reference monitor/su.test(initialDom) && initialDom.includes("Activity") && initialDom.includes("Approvals")
      ? check("PASS", `Rendered ${initialDom.length} characters of dashboard content`)
      : check("FAIL", "The served page did not contain the expected dashboard content");
    checks.frameworkOverlay = !/Application error|Internal Server Error|Vite|Next\.js|Webpack|Cannot GET/iu.test(initialDom)
      ? check("PASS", "No known framework error overlay text was rendered")
      : check("FAIL", "Known framework error overlay text was rendered");

    const semantics = await page.evaluate(() => {
      const input = document.querySelector<HTMLInputElement>("#token");
      const button = document.querySelector<HTMLButtonElement>("button");
      return { language: document.documentElement.lang, h1: document.querySelectorAll("h1").length, h2: document.querySelectorAll("h2").length, inputLabelCount: input?.labels?.length ?? 0, buttonName: button?.textContent?.trim() ?? "", tableHeaders: document.querySelectorAll("table thead th").length };
    });
    checks.semantics = semantics.language === "en" && semantics.h1 === 1 && semantics.h2 >= 2 && semantics.inputLabelCount === 1 && semantics.buttonName === "Load" && semantics.tableHeaders === 5
      ? check("PASS", `lang=${semantics.language}, h1=${semantics.h1}, h2=${semantics.h2}, labelled inputs=${semantics.inputLabelCount}, table headers=${semantics.tableHeaders}`)
      : check("FAIL", JSON.stringify(semantics));
    await page.keyboard.press("Tab");
    const focus = await page.evaluate(() => {
      const element = document.activeElement;
      if (!(element instanceof HTMLElement)) return { id: "", visible: false, outline: "none", outlineWidth: "0px", boxShadow: "none" };
      const style = getComputedStyle(element);
      return { id: element.id, visible: (style.outlineStyle !== "none" && style.outlineWidth !== "0px") || style.boxShadow !== "none", outline: style.outlineStyle, outlineWidth: style.outlineWidth, boxShadow: style.boxShadow };
    });
    checks.keyboardFocus = focus.id === "token" && focus.visible
      ? check("PASS", `Tab reached #token with outline=${focus.outline}/${focus.outlineWidth}`)
      : check("FAIL", `Focused element=${focus.id || "none"}, outline=${focus.outline}/${focus.outlineWidth}, box-shadow=${focus.boxShadow}`);
    const colors = await page.evaluate(() => {
      const body = getComputedStyle(document.body); const small = document.querySelector("small"); const smallStyle = small ? getComputedStyle(small) : body;
      return { bodyColor: body.color, bodyBackground: body.backgroundColor, smallColor: smallStyle.color };
    });
    let bodyContrast = 0; let smallContrast = 0;
    try { bodyContrast = contrastRatio(colors.bodyColor, colors.bodyBackground); smallContrast = contrastRatio(colors.smallColor, colors.bodyBackground); } catch { /* report a failed measurement below */ }
    checks.contrast = bodyContrast >= 4.5 && smallContrast >= 4.5
      ? check("PASS", `body contrast=${bodyContrast.toFixed(2)}:1, secondary text contrast=${smallContrast.toFixed(2)}:1`)
      : check("FAIL", `body contrast=${bodyContrast.toFixed(2)}:1, secondary text contrast=${smallContrast.toFixed(2)}:1; colors=${JSON.stringify(colors)}`);

    const token = page.getByLabel("Bearer token");
    await token.fill(api.token);
    const activityResponse = page.waitForResponse(item => item.url().endsWith("/api/v1/activity") && item.request().method() === "GET");
    const approvalsResponse = page.waitForResponse(item => item.url().endsWith("/api/v1/approvals") && item.request().method() === "GET");
    await page.getByRole("button", { name: "Load" }).click();
    const [activity, approvals] = await Promise.all([activityResponse, approvalsResponse]);
    apiResponses.activity = activity.status(); apiResponses.approvals = approvals.status();
    await page.getByText("No approvals.").waitFor({ state: "visible" });
    baseReport.interaction.executed = true;
    baseReport.interaction.path = "Tab to token → enter dashboard token → click Load";
    baseReport.interaction.stateChange = "Activity and approvals requests returned; approvals state changed to No approvals.";
    checks.interaction = activity.status() === 200 && approvals.status() === 200 && await page.locator("#approvals").innerText() === "No approvals."
      ? check("PASS", `GET /api/v1/activity=${activity.status()}, GET /api/v1/approvals=${approvals.status()}, visible empty-state text confirmed`)
      : check("FAIL", `activity=${activity.status()}, approvals=${approvals.status()}, approvals text=${await page.locator("#approvals").innerText()}`);

    const desktopScreenshot = join(artifactDirectory, "desktop-loaded.png");
    await page.screenshot({ path: desktopScreenshot, fullPage: true }); screenshots.push(desktopScreenshot);
    const mobile = await context.newPage();
    mobile.on("console", message => { if (message.type() === "error") consoleErrors.push(`mobile: ${message.text()}`); if (message.type() === "warning") consoleWarnings.push(`mobile: ${message.text()}`); });
    mobile.on("pageerror", error => pageErrors.push(`mobile: ${error.message}`));
    mobile.on("requestfailed", request => requestFailures.push(`mobile: ${request.method()} ${request.url()} :: ${request.failure()?.errorText ?? "unknown"}`));
    await mobile.setViewportSize({ width: 390, height: 844 });
    await mobile.goto(url, { waitUntil: "networkidle" });
    await mobile.getByLabel("Bearer token").fill(api.token);
    await mobile.getByRole("button", { name: "Load" }).click();
    await mobile.getByText("No approvals.").waitFor({ state: "visible" });
    const mobileLayout = await mobile.evaluate(() => ({ viewport: window.innerWidth, scrollWidth: document.documentElement.scrollWidth, clientWidth: document.documentElement.clientWidth }));
    const mobileScreenshot = join(artifactDirectory, "mobile-loaded.png");
    await mobile.screenshot({ path: mobileScreenshot, fullPage: true }); screenshots.push(mobileScreenshot);
    checks.responsive = mobileLayout.scrollWidth <= mobileLayout.clientWidth
      ? check("PASS", `390px viewport rendered without horizontal overflow (${mobileLayout.scrollWidth}px content / ${mobileLayout.clientWidth}px viewport)`)
      : check("FAIL", `Horizontal overflow at 390px viewport (${mobileLayout.scrollWidth}px content / ${mobileLayout.clientWidth}px viewport)`);
    checks.consoleHealth = consoleErrors.length === 0 && pageErrors.length === 0 && requestFailures.length === 0
      ? check("PASS", "No browser console errors, page errors, or failed requests during desktop/mobile interaction")
      : check("FAIL", `errors=${consoleErrors.length}, pageErrors=${pageErrors.length}, requestFailures=${requestFailures.length}`);
    const statusRegionCount = await page.locator("[aria-live], [role=\"status\"], [role=\"alert\"]").count();
    checks.screenReaderStatus = statusRegionCount > 0
      ? check("PASS", `Found ${statusRegionCount} aria-live/status/alert region(s) for asynchronous state`)
      : check("NOT_PROVEN", "No aria-live, role=status, or role=alert region was found for asynchronous loading/error state changes");
    if (statusRegionCount === 0) blockers.push("SCREEN_READER_STATUS_NOT_PROVEN");
    const reducedMotionRule = await page.evaluate(() => [...document.styleSheets].some(sheet => {
      try { return [...sheet.cssRules].some(rule => rule.cssText.includes("prefers-reduced-motion")); }
      catch { return false; }
    }));
    checks.reducedMotion = reducedMotionRule
      ? check("PASS", "The served stylesheet contains a prefers-reduced-motion rule")
      : check("NOT_PROVEN", "The served stylesheet has no prefers-reduced-motion rule; no motion behavior can be certified");
    if (!reducedMotionRule) blockers.push("REDUCED_MOTION_HANDLING_NOT_PROVEN");
    const reportStatus = Object.values(checks).some(item => item.status === "FAIL" || item.status === "UNSUPPORTED" || item.status === "NOT_PROVEN") ? "NOT_CERTIFIED" : "PASS";
    if (reportStatus !== "PASS") blockers.unshift("BROWSER_ACCESSIBILITY_CHECKS_INCOMPLETE");
    writeOutput({ ...baseReport, status: reportStatus }, jsonOnly);
    return reportStatus === "PASS" ? 0 : 1;
  } catch (error) {
    checks.browserRuntime = check("UNSUPPORTED", `Playwright browser execution failed: ${error instanceof Error ? error.message : String(error)}`);
    blockers.push("REAL_BROWSER_LAUNCH_FAILED");
    writeOutput({ ...baseReport, status: "UNSUPPORTED" }, jsonOnly);
    return 2;
  } finally {
    if (browser) await browser.close();
    await api.close();
    store.close();
  }
}

main().then(code => { process.exitCode = code; }).catch(error => { console.error(error instanceof Error ? error.stack ?? error.message : String(error)); process.exitCode = 1; });
