# Legal pages and payment-provider requirements

Section D. This page records what exists, what was added, what still needs a
human, and — importantly — why there is no payment integration to write about.

---

## 1. What exists now

| Item | Where | Status |
| --- | --- | --- |
| Privacy Policy | `safesteps/legal.html#privacy` | Written against this codebase |
| Terms of Use | `safesteps/legal.html#terms` | Written against this codebase |
| Short in-app disclaimer | `#legalDisclaimerModal` in `index.html` | Pre-existing, extended with privacy + emergency points and links to the full pages |
| Account deletion (right to erasure) | Account screen → *Delete My Account & Server Data* | **Added** — see §3 |
| Data-retention statement | Privacy Policy §5 | Matches the actual purge function |

`legal.html` is a standalone page: readable with JavaScript disabled, no app
shell, no service worker. That matters because these documents are often opened
once, by a parent, a teacher or a data-protection officer, and it will be
linked from outside the app.

## 2. These documents are written from the code, not from a template

Every factual claim in `legal.html` was checked against the repository. The
points that are easy to get wrong, and how each was verified:

| Claim | Verified by |
| --- | --- |
| "Most data stays on the device" | `localStorage` key `safesteps_state_v3`; the only other keys are `safesteps_profile`, `safesteps_pending_email`, `safesteps_fm_plan`, `ntsaLiveCache` |
| Medical note and trusted contact are never uploaded | Both live in the local `state` object; no API call sends them |
| Per-user row access is enforced by the database | 18 RLS policies across the 8 tables, all scoped to `auth.uid()` |
| Security events deleted after 365 days, mail records after 90 | `private.purge_expired_data()` in `20261104120000_security_schema.sql` |
| Passwords are hashed and never readable by us | Supabase Auth; the server never logs or returns a password |
| Passwords are 6–8 characters | `password_min_length 6` plus the app's own policy; stated in both the policy and the terms so users are not surprised |
| Weather sends coordinates to Open-Meteo | `api.open-meteo.com` calls in `index.html` |
| Integrity reports are not retained | They are composed on-device and sent to a chosen agency address; no server copy |
| No advertising, no analytics, no tracking pixels | No such SDK is loaded; the only third-party scripts are jspdf, tesseract, leaflet, qrcode and jsQR |
| SOS is not a monitored service | The button dials 112/999 via the phone; nothing is sent to the server |

If a feature changes, the corresponding sentence in `legal.html` must change with
it. A policy that drifts from the product is worse than having none, because it
is a documented false statement.

## 3. The gap this section actually found

The server had `POST /api/account/delete` and a `SECURITY DEFINER` function that
erases the caller's own rows — and **nothing in the client ever called it.** The
app therefore offered no way to delete an account, while the settings screens
talked about privacy and erasure.

That is a compliance defect, not a documentation one: the right to erasure is
meaningless if exercising it requires a support ticket. (Under Kenya's Data
Protection Act 2019 and the GDPR alike, the controller must provide a way to
erase.) Two changes:

1. `assets/security.js` — `SS.session.deleteAccount()`.
2. `index.html` — a **Delete My Account & Server Data** button on the Account
   screen, next to Sign Out, with a two-step confirmation that names exactly
   what is destroyed.

It also distinguishes the failure modes honestly, because a deletion request that
fails must not look like one that succeeded:

- session expired → "nothing was deleted, sign in and try again";
- no connection → "nothing was deleted";
- anything else → the server's own message.

Nothing is optimistically cleared from local state: the local reset happens only
after the server confirms.

### The second half of the same bug

Adding the button exposed a worse problem underneath it. `handleDeleteAccount`
erased the user's **rows** and left `auth.users` intact — so after "deleting your
account", the same email and password still signed in. The policy promised the
account was erased. It was not.

Fixed in `lib/api.js` + `lib/auth.js`:

- `auth.adminDeleteUser(userId)` removes the sign-in record via the admin API,
  treating a 404 as success so a retry after a half-finished deletion completes.
- **Order matters and is deliberate:** the sign-in record is deleted *first*, then
  the rows. The reverse looks safer but is worse — erasing rows first leaves a
  live login with no data behind it, and if step two fails the user still has a
  working account they cannot get rid of. Deleting the login first means a
  failure leaves orphaned rows that nobody can sign in to see, which is the
  strictly better failure and can be purged later.
- If the server has no service-role key, it erases the rows, clears the session
  and then **says so** (`delete_partial`) instead of reporting success. A partial
  deletion reported as complete is the one outcome a user must never see.
- These messages set `expose: true`, because `sendError` replaces every 5xx body
  with "Something went wrong" — the least useful possible answer after a
  deletion attempt.

`test/account-deletion.test.js` (6 tests) covers it: anonymous callers are
refused, the auth record is actually deleted, the session cookie is expired, a
failure is reported rather than disguised, the no-service-role fallback admits
its limit, and cross-origin requests are refused. Confirmed they fail against the
original implementation.

**Scope still stated plainly:** with a service-role key configured, both the
sign-in record and the rows are removed, so the policy's wording is accurate. The
only caveat is a deployment *without* that key, which now reports
`delete_partial` rather than lying — set `SUPABASE_SERVICE_ROLE_KEY` in any
real deployment.

## 4. Payment provider requirements — not applicable

The checklist asks about meeting payment-provider requirements *if a payment
provider is used*. There is none, and this was verified rather than assumed:

```
$ grep -rniE "stripe|paypal|mpesa|pesapal|flutterwave" --include=*.js --include=*.html .
safesteps/index.html:9808:  // ... stripEphemeralMedia ...
```

Those are the only matches, and they are the word "stripes"/"strip" in road-safety
copy. Specifically:

- **No payment SDK** is loaded. The third-party scripts are jspdf, tesseract.js,
  Leaflet, qrcodejs and jsQR — document, OCR, map and QR libraries.
- **No checkout, pricing, subscription or billing code** exists in the client,
  the server or the database migrations.
- **No card data is collected** anywhere, so no PCI-DSS scope exists.
- The Content-Security-Policy in `lib/security-headers.js` actively blocks the
  Payment Request API: `payment=()`. The app is *configured not to be able to
  take a payment*, which is the opposite of a half-built integration.
- The app is free. There is no paid tier in the product.

So there is nothing to satisfy — no Stripe account, no webhook signing secret, no
tax handling, no refund policy, no PCI attestation. Inventing a checkout flow to
"meet the requirement" would add risk (payment data, refunds, consumer-protection
duties) with no product reason. If a paid tier is ever added, this section must be
rewritten and at minimum will need: named processor and its data handling, price
and tax display, cancellation and refund terms, invoice retention, and a review of
whether minors can enter a paid contract.

## 5. Still needs a human

These cannot be done from the repository:

1. **Fill the placeholders** in `legal.html` — marked in red on the page:
   operator legal name, contact email, postal address, governing jurisdiction.
   Search for `class="placeholder"`.
2. ~~Decide the auth-record question~~ — done: the sign-in record is now deleted
   too, so the policy matches the behaviour. Ensure
   `SUPABASE_SERVICE_ROLE_KEY` is set in the deployment.
3. **Confirm the Kenya Scouts Association relationship.** The app states it was
   built with KSA as Project 360° Shield. Using another organisation's name in a
   published policy needs their written agreement.
4. **Have a Kenyan lawyer read the terms** — specifically the limitation of
   liability, the governing-law clause and the children's provisions. Kenyan
   consumer-protection law limits how far liability can be excluded, and a
   school-facing product involving minors warrants a review rather than a
   template.
5. **Register with the ODPC** if the operator meets the threshold of a data
   controller under the Data Protection Act 2019. That is an organisational
   filing, not a code change.
6. **Link the policy where it is discoverable** — the page is reachable from
   Settings and the disclaimer modal, and should also be on the Play Store /
   web listing.

## 6. Verification

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<host>/legal.html   # expect 200
```

Checked locally on 2026-11-05: `200`, `text/html`, served with the same CSP as
the app, readable with JavaScript disabled, and no horizontal overflow at 320px,
375px or 414px. Tables are wrapped in a scroll container so a long email address
cannot push the page sideways.
