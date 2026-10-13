# survey-bot-checker

Tripwire is a browser-side demo of respondent screening for online survey panels. A test survey is scored live
on timing, input behaviour, device signals and hidden honeypot fields, and a "Run the bot simulation" button
shows a scripted bot being caught.

## Checks

| Group | Signals |
|---|---|
| Honeypot | Two invisible fields (a text input and a checkbox) that people never fill |
| Timing | Completion time against a reading-speed floor; time to first interaction |
| Behaviour | Script-generated events (`isTrusted`), pointer and touch activity, key presses vs text length, typing rhythm |
| Device | `navigator.webdriver`, headless user agent, zero-size window, claimed country vs device timezone, canvas fingerprint repeat |
| Response quality | Attention-check row, straight-lining, gibberish in the open-ended answer |

Signals add weighted risk points to a 0-100 score. Under 30 is Accept, 30-59 is Review, 60 and over is Reject.

## Run it

```
npm install
npm run dev
```

## Deploy to Cloudflare Pages

The workflow in `.github/workflows/cloudflare-pages.yml` builds and deploys `dist` on every push to `main`.
Add two repository secrets (Settings > Secrets and variables > Actions):

- `CLOUDFLARE_API_TOKEN`: an API token with the "Cloudflare Pages: Edit" permission
- `CLOUDFLARE_ACCOUNT_ID`: your account ID, shown on the Cloudflare dashboard

The first run creates the `survey-bot-checker` Pages project. Without the secrets the job skips itself.

## Limits

- Everything runs in the browser, so every signal can be forged by a determined attacker. A real deployment must re-verify on a server.
- No IP, VPN, proxy or data-centre checks.
- Weights and thresholds are hand-set and have not been calibrated on real panel data.
- The repeat-device check only sees the same browser (it uses localStorage).
- Fingerprints can collide; a match should send a response to review, not reject it.
- Keyboard-only and screen-reader users produce little pointer data, so that signal has a small weight.

No data leaves the browser.
