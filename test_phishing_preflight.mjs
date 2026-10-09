import { readFileSync } from "node:fs";

const source = readFileSync("script.js", "utf8");
const start = source.indexOf("function applyPhishingPreflight");
const end = source.indexOf("/* ============================================================\n   RENDER ANALYSIS RESULT", start);
if (start < 0 || end < 0) process.exit(1);

const api = new Function(`${source.slice(start, end)}; return { applyPhishingPreflight };`)();
const failures = [];

const base = () => ({ indicators: [], recommendation: null });

const url = api.applyPhishingPreflight(base(), "http://192.0.2.10/login", "url");
if (!url.indicators.some(item => item.includes("raw IP"))) failures.push("raw IP URL was not flagged by preflight");

const puny = api.applyPhishingPreflight(base(), "https://xn--e1afmkfd.xn--p1ai/login", "url");
if (!puny.indicators.some(item => item.includes("punycode"))) failures.push("punycode URL was not flagged by preflight");

const message = api.applyPhishingPreflight(base(), "Urgent: send your OTP and password immediately", "message");
if (!message.indicators.some(item => item.includes("sensitive-information request"))) failures.push("credential request was not flagged by message preflight");

if (failures.length) {
    console.error("PHISHING PREFLIGHT TESTS FAILED");
    failures.forEach(item => console.error("-", item));
    process.exit(1);
}

console.log("PHISHING PREFLIGHT TESTS PASSED");
