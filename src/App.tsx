import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import {
  ATTENTION_ANSWER,
  COUNTRIES,
  GRID_ROWS,
  LIKERT,
  MIN_SECONDS,
  OPEN_END_PROMPT,
  collectFingerprint,
  emptyAnswers,
  evaluate,
  newTelemetry,
  score,
  verdictFor,
  type Answers,
  type Category,
  type Signal,
  type Telemetry,
} from "./detect";

const SEEN_KEY = "tripwire.seen";
const readSeen = (): string[] => {
  try {
    return JSON.parse(localStorage.getItem(SEEN_KEY) || "[]");
  } catch {
    return [];
  }
};
const writeSeen = (list: string[]) => {
  try {
    localStorage.setItem(SEEN_KEY, JSON.stringify(list));
  } catch {
    /* storage blocked: duplicate check just won't persist */
  }
};

const FREQUENCIES = ["Weekly or more", "A few times a month", "Rarely", "Never"];
const CATEGORIES: Category[] = ["Honeypot", "Timing", "Behaviour", "Device", "Response quality"];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function setNativeValue(el: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement, value: string) {
  const proto = Object.getPrototypeOf(el);
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  setter?.call(el, value);
  el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
}

export default function App() {
  const fp = useMemo(() => collectFingerprint(), []);
  const [answers, setAnswers] = useState<Answers>(emptyAnswers);
  const tele = useRef<Telemetry>(newTelemetry());
  const formRef = useRef<HTMLFormElement>(null);
  const [formKey, setFormKey] = useState(0);
  const [submittedAt, setSubmittedAt] = useState<number | null>(null);
  const [seenAtSubmit, setSeenAtSubmit] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [lastRun, setLastRun] = useState<"human" | "bot" | null>(null);
  const [, setTick] = useState(0);
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(false);

  // Re-render while the survey is open so timers stay live.
  useEffect(() => {
    if (submittedAt !== null) return;
    const id = setInterval(() => setTick((n) => n + 1), 500);
    return () => clearInterval(id);
  }, [submittedAt]);

  // Telemetry listeners, scoped to the survey form.
  useEffect(() => {
    const inForm = (e: Event) => !!formRef.current && e.target instanceof Node && formRef.current.contains(e.target);
    const markFirst = () => {
      if (tele.current.firstInteractionAt === null) tele.current.firstInteractionAt = performance.now();
    };
    let last: { x: number; y: number } | null = null;

    const onPointer = (e: PointerEvent) => {
      if (!inForm(e)) return;
      if (e.pointerType === "touch") return;
      tele.current.pointerMoves++;
      if (last) tele.current.pointerDistance += Math.hypot(e.clientX - last.x, e.clientY - last.y);
      last = { x: e.clientX, y: e.clientY };
    };
    const onTouch = (e: TouchEvent) => {
      if (inForm(e)) tele.current.touches++;
    };
    const onScroll = () => {
      tele.current.scrolls++;
    };
    const onKey = (e: KeyboardEvent) => {
      if (!inForm(e)) return;
      if (!e.isTrusted) tele.current.untrustedEvents++;
      markFirst();
      const t = tele.current;
      t.keydowns++;
      const now = performance.now();
      if (t.lastKeyAt !== null) t.keyIntervals.push(now - t.lastKeyAt);
      t.lastKeyAt = now;
      if ((e.target as HTMLElement).id === "openEnd") t.openEndKeydowns++;
    };
    const onPaste = (e: Event) => {
      if (inForm(e)) tele.current.pastes++;
    };
    const onInteract = (e: Event) => {
      if (!inForm(e)) return;
      const target = e.target as HTMLElement;
      if (target.closest("[data-honeypot]")) {
        if (!e.isTrusted) tele.current.untrustedEvents++;
        return;
      }
      if (!e.isTrusted) tele.current.untrustedEvents++;
      markFirst();
    };

    window.addEventListener("pointermove", onPointer, { passive: true });
    window.addEventListener("touchstart", onTouch, { passive: true });
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("keydown", onKey, true);
    window.addEventListener("paste", onPaste, true);
    window.addEventListener("input", onInteract, true);
    window.addEventListener("change", onInteract, true);
    window.addEventListener("click", onInteract, true);
    return () => {
      window.removeEventListener("pointermove", onPointer);
      window.removeEventListener("touchstart", onTouch);
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("paste", onPaste, true);
      window.removeEventListener("input", onInteract, true);
      window.removeEventListener("change", onInteract, true);
      window.removeEventListener("click", onInteract, true);
    };
  }, []);

  const seenLive = submittedAt === null ? readSeen().includes(fp.canvasHash) : seenAtSubmit;
  const signals = evaluate(answers, tele.current, fp, submittedAt, seenLive);
  const risk = score(signals);
  const verdict = verdictFor(risk);
  const flagged = signals.filter((s) => s.severity !== "pass");

  const reset = useCallback(() => {
    setAnswers(emptyAnswers());
    tele.current = newTelemetry();
    setSubmittedAt(null);
    setSeenAtSubmit(false);
    setShowJson(false);
    setFormKey((k) => k + 1);
  }, []);

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const seen = readSeen();
    const already = seen.includes(fp.canvasHash);
    if (!already) writeSeen([...seen, fp.canvasHash]);
    setSeenAtSubmit(already);
    setSubmittedAt(performance.now());
    if (!simulating) setLastRun("human");
  };

  const clearDevice = () => {
    writeSeen([]);
    setSeenAtSubmit(false);
    setTick((n) => n + 1);
  };

  const runBot = async () => {
    if (simulating) return;
    setSimulating(true);
    setLastRun("bot");
    reset();
    await sleep(120);
    const f = formRef.current;
    if (!f) return setSimulating(false);
    const q = <T extends Element>(sel: string) => f.querySelector<T>(sel);
    const mismatch = COUNTRIES.find((c) => !c.tz.test(fp.timezone))?.name ?? "India";

    const country = q<HTMLSelectElement>("#country");
    if (country) setNativeValue(country, mismatch);
    await sleep(60);
    q<HTMLInputElement>('input[name="frequency"]')?.click();
    await sleep(60);
    for (const row of GRID_ROWS) {
      q<HTMLInputElement>(`input[name="${row.id}"][value="Agree"]`)?.click();
      await sleep(40);
    }
    const open = q<HTMLTextAreaElement>("#openEnd");
    if (open) setNativeValue(open, "good service good price good good good good");
    await sleep(60);
    const hp = q<HTMLInputElement>("#hp-website");
    if (hp) setNativeValue(hp, "https://cheap-offers.example");
    q<HTMLInputElement>("#hp-confirm")?.click();
    await sleep(80);
    f.requestSubmit();
    setSimulating(false);
  };

  const payload = {
    respondent: { device: fp.canvasHash, timezone: fp.timezone, claimedCountry: answers.country || null },
    riskScore: risk,
    verdict,
    completedInSeconds: submittedAt ? +((submittedAt - tele.current.mountedAt) / 1000).toFixed(1) : null,
    flags: flagged.map((s) => ({ id: s.id, severity: s.severity, points: s.severity === "flag" ? s.weight : Math.round(s.weight / 2), detail: s.detail })),
  };
  const payloadText = JSON.stringify(payload, null, 2);

  const copyPayload = async () => {
    try {
      await navigator.clipboard.writeText(payloadText);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      const pre = document.getElementById("payload");
      if (pre) {
        const range = document.createRange();
        range.selectNodeContents(pre);
        const sel = window.getSelection();
        sel?.removeAllRanges();
        sel?.addRange(range);
      }
    }
  };

  const setGrid = (row: string, v: string) => setAnswers((a) => ({ ...a, grid: { ...a.grid, [row]: v } }));
  const locked = submittedAt !== null;

  return (
    <div className="page">
      <header className="topbar">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
            <path d="M1 15 H7 L9 9 L13 19 L15 13 H21" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <span>Tripwire</span>
        </div>
        <span className="tag">Live demo · runs in your browser</span>
      </header>

      <section className="hero">
        <p className="eyebrow">Respondent quality screening for survey panels</p>
        <h1>Stop paying incentives for answers a script wrote.</h1>
        <p className="lede">
          Tripwire watches how a survey is completed, not just what was answered. Timing, input behaviour, device
          signals and hidden trap fields roll up into one risk score you can act on before the reward is credited.
        </p>
        <div className="hero-actions">
          <button type="button" className="btn primary" onClick={runBot} disabled={simulating}>
            {simulating ? "Bot is filling the survey…" : "Run the bot simulation"}
          </button>
          <a className="btn ghost" href="#survey">
            Take the survey yourself
          </a>
        </div>
        <p className="hint">Answer it honestly first, then run the bot and compare the two scores.</p>
      </section>

      <main className="demo" id="survey">
        <form ref={formRef} key={formKey} className="survey" onSubmit={onSubmit} noValidate autoComplete="off">
          <div className="survey-head">
            <span className="mono small">Study GD-2611 · Grocery delivery habits</span>
            <span className="mono small">≈ 2 min · 4 questions</span>
          </div>

          <fieldset disabled={locked}>
            <div className="q">
              <label htmlFor="country" className="q-label">
                <span className="q-num">Q1</span> Which country do you live in?
              </label>
              <select
                id="country"
                value={answers.country}
                onChange={(e) => setAnswers((a) => ({ ...a, country: e.target.value }))}
              >
                <option value="">Select a country</option>
                {COUNTRIES.map((c) => (
                  <option key={c.name} value={c.name}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="q" role="radiogroup" aria-labelledby="q2">
              <p id="q2" className="q-label">
                <span className="q-num">Q2</span> How often do you order groceries online?
              </p>
              <div className="choices">
                {FREQUENCIES.map((f) => (
                  <label key={f} className="choice">
                    <input
                      type="radio"
                      id={`freq-${f}`}
                      name="frequency"
                      value={f}
                      checked={answers.frequency === f}
                      onChange={() => setAnswers((a) => ({ ...a, frequency: f }))}
                    />
                    <span>{f}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="q">
              <p className="q-label">
                <span className="q-num">Q3</span> How much do you agree with each statement?
              </p>
              <div className="grid-wrap">
                <table className="likert">
                  <thead>
                    <tr>
                      <th scope="col">
                        <span className="sr">Statement</span>
                      </th>
                      {LIKERT.map((l) => (
                        <th key={l} scope="col">
                          {l}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {GRID_ROWS.map((row) => (
                      <tr key={row.id}>
                        <th scope="row">{row.text}</th>
                        {LIKERT.map((l) => (
                          <td key={l}>
                            <input
                              type="radio"
                              id={`${row.id}-${l}`}
                              name={row.id}
                              value={l}
                              aria-label={`${row.text} ${l}`}
                              checked={answers.grid[row.id] === l}
                              onChange={() => setGrid(row.id, l)}
                            />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="q">
              <label htmlFor="openEnd" className="q-label">
                <span className="q-num">Q4</span> {OPEN_END_PROMPT}
              </label>
              <textarea
                id="openEnd"
                rows={3}
                value={answers.openEnd}
                onChange={(e) => setAnswers((a) => ({ ...a, openEnd: e.target.value }))}
                placeholder="A sentence or two in your own words"
              />
            </div>

            {/* Honeypots: off-screen, hidden from assistive tech, skipped by Tab. */}
            <div className="honeypot" data-honeypot aria-hidden="true">
              <label htmlFor="hp-website">Website</label>
              <input
                id="hp-website"
                name="website"
                type="text"
                tabIndex={-1}
                autoComplete="off"
                value={answers.hpWebsite}
                onChange={(e) => setAnswers((a) => ({ ...a, hpWebsite: e.target.value }))}
              />
              <label htmlFor="hp-confirm">Confirm email</label>
              <input
                id="hp-confirm"
                name="confirm_email"
                type="checkbox"
                tabIndex={-1}
                checked={answers.hpConfirm}
                onChange={(e) => setAnswers((a) => ({ ...a, hpConfirm: e.target.checked }))}
              />
            </div>
          </fieldset>

          <div className="survey-foot">
            {locked ? (
              <button type="button" className="btn primary" onClick={reset}>
                Start a fresh response
              </button>
            ) : (
              <button type="submit" className="btn primary">
                Submit response
              </button>
            )}
            <span className="mono small muted">Reading floor {MIN_SECONDS} s</span>
          </div>
        </form>

        <aside className="inspector" aria-live="polite">
          <div className="insp-head">
            <div>
              <p className="eyebrow">{locked ? `Final screening${lastRun === "bot" ? " · simulated bot" : ""}` : "Live screening"}</p>
              <div className="score-row">
                <span className="score mono">{risk}</span>
                <span className="score-of mono">/ 100 risk</span>
                <span className={`verdict v-${verdict.toLowerCase()}`}>{locked ? verdict : `Trending ${verdict.toLowerCase()}`}</span>
              </div>
            </div>
          </div>
          <div className="meter" aria-hidden="true">
            <div className="meter-fill" style={{ width: `${risk}%` }} />
            <span className="tick" style={{ left: "30%" }} />
            <span className="tick" style={{ left: "60%" }} />
          </div>
          <div className="meter-legend mono small muted">
            <span>Accept</span>
            <span>Review 30</span>
            <span>Reject 60</span>
          </div>

          {CATEGORIES.map((cat) => (
            <div className="sig-group" key={cat}>
              <h3>{cat}</h3>
              <ul>
                {signals
                  .filter((s) => s.category === cat)
                  .map((s: Signal) => (
                    <li key={s.id} className={`sig sev-${s.severity}`}>
                      <span className="pill">{s.severity === "pass" ? "OK" : s.severity === "warn" ? "Weak" : "Flag"}</span>
                      <div className="sig-body">
                        <div className="sig-top">
                          <span className="sig-label">{s.label}</span>
                          {s.severity !== "pass" && (
                            <span className="mono small pts">+{s.severity === "flag" ? s.weight : Math.round(s.weight / 2)}</span>
                          )}
                        </div>
                        <p className="sig-detail">{s.detail}</p>
                      </div>
                    </li>
                  ))}
              </ul>
            </div>
          ))}

          <div className="insp-foot">
            <button type="button" className="btn ghost small-btn" onClick={() => setShowJson((v) => !v)}>
              {showJson ? "Hide" : "Show"} server payload
            </button>
            <button type="button" className="btn ghost small-btn" onClick={clearDevice}>
              Forget this device
            </button>
          </div>
          {showJson && (
            <div className="payload">
              <div className="payload-bar">
                <span className="mono small muted">POST /api/screen</span>
                <button type="button" className="link-btn" onClick={copyPayload}>
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <pre id="payload" className="mono">{payloadText}</pre>
            </div>
          )}
        </aside>
      </main>

      <section className="section">
        <h2>What it screens for</h2>
        <div className="table-wrap">
          <table className="matrix">
            <thead>
              <tr>
                <th>Fraud pattern</th>
                <th>How Tripwire spots it</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Form-filling bots</td>
                <td>Hidden trap fields, script-generated events, webdriver and headless browser markers</td>
              </tr>
              <tr>
                <td>Speeders</td>
                <td>Completion time against a reading-speed floor, and how soon the first answer lands after load</td>
              </tr>
              <tr>
                <td>Straight-liners and skimmers</td>
                <td>Identical answers across a grid, and an embedded instruction check</td>
              </tr>
              <tr>
                <td>Duplicate respondents</td>
                <td>A canvas-based device fingerprint compared against earlier completes</td>
              </tr>
              <tr>
                <td>Geo-fraud</td>
                <td>Claimed country compared with the device clock's timezone</td>
              </tr>
              <tr>
                <td>Low-effort open ends</td>
                <td>Length, gibberish patterns, echoed question text, and key presses compared with characters entered</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section className="section two-col">
        <div>
          <h2>How it plugs in</h2>
          <p>
            One script tag on the survey page. Tripwire collects signals while the respondent works and posts a scored
            payload to your server when they submit. Your server re-scores it, adds IP and network reputation, and
            decides whether to credit the incentive.
          </p>
          <p className="muted small">Illustrative API for the planned package. The demo above runs the same checks inline.</p>
        </div>
        <pre className="code mono">{`<script src="/tripwire.min.js"></script>
<script>
  Tripwire.attach("#survey", {
    minSeconds: ${MIN_SECONDS},
    attention: { attn: "${ATTENTION_ANSWER}" },
    honeypots: ["website", "confirm_email"],
    onSubmit: (result) =>
      fetch("/api/screen", {
        method: "POST",
        body: JSON.stringify(result),
      }),
  });
</script>`}</pre>
      </section>

      <section className="section">
        <h2>Known limits of this build</h2>
        <ul className="limits">
          <li>Every browser-side signal can be forged by a determined attacker. The scores are a first filter, and the server must verify them.</li>
          <li>No IP, VPN, proxy or data-centre checks yet. Those need a server and a reputation data source.</li>
          <li>Device fingerprints change and collide. A repeat-device match should send a response to review, not reject it outright.</li>
          <li>Weights and thresholds are set by hand for the demo and have not been calibrated on real panel data.</li>
          <li>Keyboard-only and screen-reader users produce little pointer data, so that signal carries a small weight.</li>
        </ul>
      </section>

      <footer className="foot mono small muted">Tripwire demo · no data leaves your browser</footer>
    </div>
  );
}
