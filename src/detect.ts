// Tripwire detection engine. All checks run client-side for the demo.
// In production every signal here must be re-verified server-side: anything
// collected in the browser can be forged by a determined attacker.

export type Severity = "pass" | "warn" | "flag";
export type Category = "Honeypot" | "Timing" | "Behaviour" | "Device" | "Response quality";

export interface Signal {
  id: string;
  label: string;
  category: Category;
  severity: Severity;
  weight: number; // risk points added when severity !== "pass"
  detail: string;
}

export interface Telemetry {
  mountedAt: number;
  firstInteractionAt: number | null;
  pointerMoves: number;
  pointerDistance: number;
  touches: number;
  scrolls: number;
  keydowns: number;
  pastes: number;
  untrustedEvents: number;
  keyIntervals: number[];
  lastKeyAt: number | null;
  openEndKeydowns: number;
  questionFirstTouch: Record<string, number>;
}

export const newTelemetry = (): Telemetry => ({
  mountedAt: performance.now(),
  firstInteractionAt: null,
  pointerMoves: 0,
  pointerDistance: 0,
  touches: 0,
  scrolls: 0,
  keydowns: 0,
  pastes: 0,
  untrustedEvents: 0,
  keyIntervals: [],
  lastKeyAt: null,
  openEndKeydowns: 0,
  questionFirstTouch: {},
});

export interface Answers {
  country: string;
  frequency: string;
  grid: Record<string, string>;
  openEnd: string;
  hpWebsite: string;
  hpConfirm: boolean;
}

export const emptyAnswers = (): Answers => ({
  country: "",
  frequency: "",
  grid: {},
  openEnd: "",
  hpWebsite: "",
  hpConfirm: false,
});

export interface Fingerprint {
  webdriver: boolean;
  headlessUA: boolean;
  noLanguages: boolean;
  noPlugins: boolean;
  zeroOuter: boolean;
  timezone: string;
  cores: number | null;
  screen: string;
  canvasHash: string;
  userAgent: string;
}

function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

export function collectFingerprint(): Fingerprint {
  const nav = navigator as Navigator & { webdriver?: boolean };
  let canvasHash = "unavailable";
  try {
    const c = document.createElement("canvas");
    c.width = 240;
    c.height = 60;
    const ctx = c.getContext("2d");
    if (ctx) {
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(100, 5, 80, 30);
      ctx.fillStyle = "#069";
      ctx.fillText("Tripwire,fp 1.0 \u{1F50D}", 4, 12);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("Tripwire,fp 1.0", 6, 30);
      canvasHash = fnv1a(c.toDataURL());
    }
  } catch {
    /* canvas blocked: leave as unavailable */
  }
  return {
    webdriver: nav.webdriver === true,
    headlessUA: /HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium/i.test(nav.userAgent),
    noLanguages: !nav.languages || nav.languages.length === 0,
    noPlugins: /Chrome/.test(nav.userAgent) && !/Mobile|Android/.test(nav.userAgent) && (nav.plugins?.length ?? 0) === 0,
    zeroOuter: window.outerWidth === 0 || window.outerHeight === 0,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
    cores: nav.hardwareConcurrency ?? null,
    screen: `${screen.width}x${screen.height}@${window.devicePixelRatio}`,
    canvasHash,
    userAgent: nav.userAgent,
  };
}

// Timezone prefixes that are consistent with each country a respondent can claim.
export const COUNTRIES: { name: string; tz: RegExp }[] = [
  { name: "Australia", tz: /^Australia\// },
  { name: "United States", tz: /^(America\/|US\/|Pacific\/Honolulu)/ },
  { name: "United Kingdom", tz: /^Europe\/(London|Belfast)/ },
  { name: "Canada", tz: /^(America\/|Canada\/)/ },
  { name: "New Zealand", tz: /^(Pacific\/Auckland|Pacific\/Chatham|NZ)/ },
  { name: "India", tz: /^Asia\/(Kolkata|Calcutta)/ },
];

export const GRID_ROWS = [
  { id: "g1", text: "Delivery fees put me off ordering online." },
  { id: "g2", text: "I trust the shopper to pick good fresh produce." },
  { id: "attn", text: "To show you are reading carefully, select “Disagree” for this row." },
  { id: "g3", text: "I would pay more for a one-hour delivery window." },
  { id: "g4", text: "Substituted items are usually acceptable to me." },
];
export const LIKERT = ["Strongly disagree", "Disagree", "Neutral", "Agree", "Strongly agree"];
export const ATTENTION_ANSWER = "Disagree";

export const OPEN_END_PROMPT = "What would make you switch to a different grocery delivery service?";

// Floor for a genuine read-through: ~300 wpm reading plus 2 s per decision.
export const SURVEY_WORDS = 120;
export const DECISIONS = 8;
export const MIN_SECONDS = Math.round((SURVEY_WORDS / 300) * 60 + DECISIONS * 2);

function looksLikeGibberish(t: string): string | null {
  const s = t.trim();
  if (s.length === 0) return "empty";
  if (s.length < 12) return `only ${s.length} characters`;
  const letters = s.replace(/[^a-z]/gi, "");
  const vowels = letters.replace(/[^aeiou]/gi, "").length;
  if (letters.length > 8 && vowels / letters.length < 0.2) return "almost no vowels";
  if (/(.)\1{4,}/.test(s)) return "repeated characters";
  if (!/\s/.test(s) && s.length > 14) return "no word breaks";
  const words = s.toLowerCase().split(/\s+/);
  if (words.length >= 4 && new Set(words).size / words.length < 0.4) return "same words repeated";
  const prompt = OPEN_END_PROMPT.toLowerCase();
  if (prompt.includes(s.toLowerCase()) && s.length > 15) return "echoes the question text";
  return null;
}

export function evaluate(
  a: Answers,
  t: Telemetry,
  fp: Fingerprint,
  submittedAt: number | null,
  seenBefore: boolean,
): Signal[] {
  const now = submittedAt ?? performance.now();
  const elapsed = (now - t.mountedAt) / 1000;
  const out: Signal[] = [];

  // Honeypots
  const hpHit = a.hpWebsite.length > 0 || a.hpConfirm;
  out.push({
    id: "honeypot",
    label: "Hidden trap fields",
    category: "Honeypot",
    severity: hpHit ? "flag" : "pass",
    weight: 40,
    detail: hpHit
      ? `Invisible field filled (${[a.hpWebsite && "website", a.hpConfirm && "confirm box"].filter(Boolean).join(", ")}). Humans never see these.`
      : "Both invisible fields left empty.",
  });

  // Timing
  if (submittedAt !== null) {
    const ratio = elapsed / MIN_SECONDS;
    out.push({
      id: "speed",
      label: "Completion speed",
      category: "Timing",
      severity: ratio < 0.5 ? "flag" : ratio < 1 ? "warn" : "pass",
      weight: ratio < 0.5 ? 30 : 15,
      detail: `${elapsed.toFixed(1)} s against a ${MIN_SECONDS} s reading floor (${Math.round(ratio * 100)}%).`,
    });
  } else {
    out.push({
      id: "speed",
      label: "Completion speed",
      category: "Timing",
      severity: "pass",
      weight: 0,
      detail: `${elapsed.toFixed(0)} s so far. Floor for a genuine read-through is ${MIN_SECONDS} s.`,
    });
  }

  const firstLatency = t.firstInteractionAt ? (t.firstInteractionAt - t.mountedAt) / 1000 : null;
  out.push({
    id: "first",
    label: "Time to first interaction",
    category: "Timing",
    severity: firstLatency !== null && firstLatency < 0.8 ? "flag" : "pass",
    weight: 10,
    detail:
      firstLatency === null
        ? "Waiting for the first input."
        : `${firstLatency.toFixed(2)} s after load${firstLatency < 0.8 ? ", faster than a person can read the first question" : ""}.`,
  });

  // Behaviour
  out.push({
    id: "trusted",
    label: "Scripted input events",
    category: "Behaviour",
    severity: t.untrustedEvents > 0 ? "flag" : "pass",
    weight: 35,
    detail:
      t.untrustedEvents > 0
        ? `${t.untrustedEvents} events were generated by script (isTrusted = false).`
        : "Every input event came from a real device.",
  });

  const anyPointer = t.pointerMoves > 0 || t.touches > 0;
  out.push({
    id: "pointer",
    label: "Pointer and touch activity",
    category: "Behaviour",
    severity: submittedAt !== null && !anyPointer ? "warn" : "pass",
    weight: 10,
    detail: `${t.pointerMoves} moves, ${Math.round(t.pointerDistance)} px travelled, ${t.touches} touches, ${t.scrolls} scrolls.${!anyPointer ? " Keyboard-only users exist, so this alone is weak." : ""}`,
  });

  const typed = a.openEnd.trim().length;
  const programmatic = typed > 20 && t.openEndKeydowns < typed * 0.3 && t.pastes === 0;
  out.push({
    id: "typing",
    label: "Keystrokes vs text length",
    category: "Behaviour",
    severity: programmatic ? "flag" : t.pastes > 0 ? "warn" : "pass",
    weight: programmatic ? 20 : 5,
    detail: programmatic
      ? `${typed} characters appeared with only ${t.openEndKeydowns} key presses and no paste.`
      : t.pastes > 0
        ? `${t.pastes} paste event(s) in the open-ended answer.`
        : `${t.openEndKeydowns} key presses for ${typed} characters.`,
  });

  const iv = t.keyIntervals.filter((x) => x < 2000);
  let cadenceSev: Severity = "pass";
  let cadenceDetail = `Needs 15 keystrokes to judge (have ${iv.length}).`;
  if (iv.length >= 15) {
    const mean = iv.reduce((s, x) => s + x, 0) / iv.length;
    const sd = Math.sqrt(iv.reduce((s, x) => s + (x - mean) ** 2, 0) / iv.length);
    const cv = sd / mean;
    cadenceSev = cv < 0.15 ? "flag" : "pass";
    cadenceDetail = `Mean gap ${mean.toFixed(0)} ms, variation ${(cv * 100).toFixed(0)}%. ${cv < 0.15 ? "Metronome-even rhythm." : "Irregular, as people type."}`;
  }
  out.push({
    id: "cadence",
    label: "Typing rhythm",
    category: "Behaviour",
    severity: cadenceSev,
    weight: 15,
    detail: cadenceDetail,
  });

  // Device
  const autoFlags = [fp.webdriver && "navigator.webdriver", fp.headlessUA && "headless user agent", fp.zeroOuter && "zero-size window"].filter(Boolean);
  out.push({
    id: "automation",
    label: "Automation framework",
    category: "Device",
    severity: autoFlags.length ? "flag" : "pass",
    weight: 35,
    detail: autoFlags.length ? `Detected: ${autoFlags.join(", ")}.` : "No webdriver flag, headless agent or zero-size window.",
  });

  const thin = [fp.noLanguages && "no languages", fp.noPlugins && "no plugins on desktop Chrome"].filter(Boolean);
  out.push({
    id: "thin",
    label: "Browser completeness",
    category: "Device",
    severity: thin.length ? "warn" : "pass",
    weight: 5,
    detail: thin.length ? `Unusual profile: ${thin.join(", ")}.` : `${fp.cores ?? "?"} cores, ${fp.screen} screen.`,
  });

  const country = COUNTRIES.find((c) => c.name === a.country);
  const geoMismatch = !!country && !country.tz.test(fp.timezone);
  out.push({
    id: "geo",
    label: "Claimed country vs device clock",
    category: "Device",
    severity: geoMismatch ? "flag" : "pass",
    weight: 15,
    detail: !country
      ? `Device timezone ${fp.timezone}. No country chosen yet.`
      : geoMismatch
        ? `Claims ${a.country}, device is set to ${fp.timezone}.`
        : `${a.country} matches ${fp.timezone}.`,
  });

  out.push({
    id: "dupe",
    label: "Repeat device",
    category: "Device",
    severity: seenBefore ? "flag" : "pass",
    weight: 25,
    detail: seenBefore
      ? `Fingerprint ${fp.canvasHash} already completed this survey in this browser.`
      : `Fingerprint ${fp.canvasHash} not seen before.`,
  });

  // Response quality
  const attn = a.grid["attn"];
  out.push({
    id: "attention",
    label: "Attention check",
    category: "Response quality",
    severity: attn && attn !== ATTENTION_ANSWER ? "flag" : "pass",
    weight: 25,
    detail: !attn ? "Not answered yet." : attn === ATTENTION_ANSWER ? "Answered correctly." : `Chose “${attn}” instead of “${ATTENTION_ANSWER}”.`,
  });

  const realRows = GRID_ROWS.filter((r) => r.id !== "attn").map((r) => a.grid[r.id]);
  const allAnswered = realRows.every(Boolean);
  const straight = allAnswered && new Set(realRows).size === 1;
  out.push({
    id: "straight",
    label: "Straight-lining",
    category: "Response quality",
    severity: straight ? "flag" : "pass",
    weight: 15,
    detail: !allAnswered ? "Grid incomplete." : straight ? `Same answer on every row (“${realRows[0]}”).` : "Answers vary across the grid.",
  });

  const gib = a.openEnd ? looksLikeGibberish(a.openEnd) : null;
  out.push({
    id: "openend",
    label: "Open-ended answer quality",
    category: "Response quality",
    severity: gib ? "flag" : "pass",
    weight: 15,
    detail: !a.openEnd ? "Not answered yet." : gib ? `Low quality: ${gib}.` : `${a.openEnd.trim().split(/\s+/).length} words, readable.`,
  });

  return out;
}

export function score(signals: Signal[]): number {
  return Math.min(
    100,
    signals.reduce((s, x) => s + (x.severity === "flag" ? x.weight : x.severity === "warn" ? Math.round(x.weight / 2) : 0), 0),
  );
}

export type Verdict = "Accept" | "Review" | "Reject";
export const verdictFor = (s: number): Verdict => (s >= 60 ? "Reject" : s >= 30 ? "Review" : "Accept");
