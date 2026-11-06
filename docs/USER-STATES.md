# User States & Edge Cases

Every state below is implemented in `safesteps/index.html`, reachable from real
code (not just defined), and verified by `scripts/check-states.js`, which executes
the page's own functions in a DOM and asserts on the rendered markup, ARIA roles
and wired actions. That script gates CI.

The rule behind all ten: **no state may be a dead end.** Each one says what
happened, what the user can do next, and — where something failed — that the
rest of the screen still works.

| # | State | Implementation | What the user sees |
| - | ----- | -------------- | ------------------ |
| 1 | Empty | `renderEmptyState()` | Icon, title, one line of context, and an action button (e.g. "No reports near you yet" → submit one). |
| 2 | Loading | `renderSkeleton()` | Shimmer cards with `aria-busy="true"` and an `.sr-only` label ("Loading lessons…") so screen readers hear progress instead of silence. |
| 3 | Error | `renderErrorState()` | `role="alert"`, a plain-language reason, and a wired retry button. |
| 4 | No internet | `ConnectionState` + `#connectionBanner` | Banner flips to "You're offline" (`is-offline`), everything already loaded stays usable, and it retries automatically. |
| 5 | Slow network | `ConnectionState` (`is-slow`) | "Slow connection" with the option to retry rather than an indefinite spinner. Returns to "Back online" then hides itself. |
| 6 | No search results | `renderNoResults()` | Echoes the query, lists real alternatives from the directory, and offers "Show all SACCOs". |
| 7 | Permission denied | `explainPermissionError()` + `showPermissionHelp()` | Distinguishes blocked / missing device / busy camera / unsupported / timeout, each with its own fix, icon and alternative route. |
| 8 | Session expired | `window.onSessionExpired()` | `role="alertdialog"` card that saves in-progress work, reassures the user nothing was lost, and offers resume or dismiss. |
| 9 | Form validation | `setFieldError()` / `clearFieldError()` | Errors appear inline on the exact field, with `aria-invalid`, and clear as the user fixes them. Never one generic error at the top. |
| 10 | Success | `showSuccessToast()` + `.next-step-highlight` | Confirms the save, then pulses the next action so the user knows what to do now. |

## 6. No search results

`renderNoResults` was defined and reviewed but **never called** — the SACCO
lookup still showed a bare "no registered SACCO matches" banner. It is now wired
into `searchMatatuSacco()`. Because a bare "no match" is a dead end, the empty
state:

- repeats the query back (`No match for "…"`) so typos are obvious;
- suggests trying just the SACCO name, and lists names that really exist in the
  directory (`sampleSaccos`), so the user can pick one instead of guessing;
- reminds them to check the NTSA PSV sticker before boarding;
- offers a one-tap "Show all SACCOs" that clears the box and re-runs the search.

## 7. Permission denied

Four places request a device permission — location (attach to a report, and
SOS), the camera (sign scanner), the camera again (QR sync), and the microphone
(voice commands). All of them used to collapse every failure into one string:
*"Couldn't access the camera (permission denied or unavailable)"*, or for the
microphone *"check permissions"* — which is wrong when the device has no
microphone at all. Those sentences told the user nothing about what to do.

`explainPermissionError(err)` now maps the real browser errors:

| Error | Kind | Title | Guidance |
| ----- | ---- | ----- | -------- |
| `NotAllowedError`, `PermissionDeniedError`, geo code 1 | `denied` | You've blocked access | Tap the padlock (or ⓘ) in the address bar → Permissions → Allow, then try again |
| `NotFoundError`, geo code 2 | `unavailable` | Not available on this device | Continue without it — upload a photo, or type the details |
| `NotReadableError`, `TrackStartError` | `busy` | In use by another app | Close the other app or tab, then try again |
| `OverconstrainedError` | `unsupported` | Not supported here | Upload a photo instead |
| geo code 3, `TimeoutError` | `timeout` | Took too long | Move somewhere more open, or go ahead without it |
| anything else | `unknown` | Couldn't access it | Continue without it — nothing else on this screen is affected |

`showPermissionHelp(target, err, alternative)` renders the explanation into the
host element below the control that triggered it, as `role="alert"` so it is
announced, plus an optional alternative route (e.g. "Paste the share code
instead — it always works and needs no camera"). It also calls
`announceToScreenReader` with the title and fix.

### The SOS path must never dead-end

An emergency is the worst possible moment to show "permission denied" and stop.
If location is refused during SOS, the user gets the explanation **and** a way
through: a landmark box (`#sosLandmarkInput`) and
`shareAreaWithoutLocation()`, which sends the emergency message via
`navigator.share` or WhatsApp with the named landmark instead of a pin. A message
saying roughly where you are beats no message.

The icon matches the cause. A padlock on "not available on this device" sends
the user to change a permission that was never the problem, so each kind gets
its own: 🔒 blocked, 📵 unavailable, ⏳ busy, 🚫 unsupported, ⌛ timeout, ⚠️ unknown.

Voice commands need one translation step first: `SpeechRecognition` reports
`not-allowed`, `service-not-allowed` and `audio-capture` rather than the
`getUserMedia` error names, so the handler maps them before asking for the
explanation. It also turns the toggle back off, because leaving a switch on
that can never work is worse than saying so.

Every permission message ends by stating that the rest of the screen still
works — a blocked permission is a limitation, not a failure of the app.

## Verifying

```
npm install --no-save happy-dom      # dev-only, never shipped to the browser
node scripts/check-states.js         # exit 1 if any of the ten states is broken
```

Expected tail:

```
All 53 state checks passed — every one of the ten states is reachable and behaves.
No browser engine here: this proves markup, roles and logic, not paint timing.
```

The checker is deliberately able to fail. Collapsing `NotReadableError` back into
the generic branch, removing `#sosLocationHelp`, or renaming the `renderNoResults`
call site each make it exit 1 — verified by injecting all three into a copy of
the page.

There is no browser engine in this environment, so these checks prove the
markup, ARIA roles, and logic — not paint timings or how the banner looks on a
real mid-range Android. That manual pass is still required before launch.
