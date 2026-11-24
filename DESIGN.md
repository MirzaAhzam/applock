# DESIGN.md: AppLock visual and writing direction

The anti-slop rulebook is a **filter**: it removes generic AI-looking UI, text and code, but it does not choose a direction. **This file is the direction.** Agents read it before any UI work and finish with the antislop Delivery Gate report. The owner may edit any value here; agents must not change it on their own.

Status: proposed direction, awaiting owner approval. Values marked **[owner]** are the most likely to be changed.

---

## 1. Character

**A quiet, exact, trustworthy tool.** AppLock guards something personal, so the interface should feel like a well-made lock: plain, solid, and calm. It says what it does and gets out of the way.

| It is | It is not |
|---|---|
| Plain, precise, steady | Flashy, "futuristic", gamified |
| Native-feeling on Windows 10 and 11 | A web page in a window |
| Fast to read in a second at the lock screen | A dashboard full of cards |
| Honest about limits | Full of security hype and badges |

One memorable detail (the "liveliness" antislop asks for): the lock screen shows the **real icon and name of the app being unlocked**, large and centered, so the user instantly knows what they are unlocking. The only motion is the state change: a short, firm shake of the field on a wrong PIN, and a quick fade-out on success.

## 2. Colors **[owner]**

Defined once as tokens in `ui/tokens.slint`. Components never use raw hex values. Light and dark follow the Windows setting, with a manual override.

| Token | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#F6F5F2` | `#121413` | Window background |
| `surface` | `#FFFFFF` | `#1B1D1C` | Panels, fields |
| `text` | `#16181D` | `#ECEBE6` | Main text |
| `text-muted` | `#5A5F6B` | `#A3A8A2` | Secondary text |
| `border` | `#D9D6CF` | `#2E3230` | Lines, field outlines |
| `accent` | `#0B6B5D` | `#4FD1B5` | Primary button, focus ring, toggles on |
| `on-accent` | `#FFFFFF` | `#0A1A16` | Text on accent |
| `danger` | `#B3261E` | `#F2837B` | Errors, wrong attempt, destructive actions |
| `warning` | `#8A5A00` | `#E5B04A` | Lockout, limits notices |

Rules:
- One accent color only. Deep teal-green was chosen on purpose: it avoids the default blue-purple gradient look and reads as calm and secure.
- **No gradients, no glow, no glass/blur effects, no drop-shadow stacks.** Separation comes from spacing and 1 px borders.
- Every text/background pair must meet WCAG AA (4.5:1 body, 3:1 large text and UI parts). Verify with the contrast checker that ships with antislop. Never show state by color alone; add text or an icon.

## 3. Typography

| Role | Font | Size / weight |
|---|---|---|
| UI (English) | **Segoe UI Variable** (Windows 11), fallback Segoe UI | 14 px body, 12 px caption, 20 px title, 28 px lock-screen app name |
| UI (Urdu) | **Urdu Typesetting** / **Nirmala UI** (installed with Windows) | Sizes 2 px larger; line height 1.6 |
| PIN digits | Segoe UI Variable, tabular figures | 24 px, weight 600 |

- **System fonts only.** No font files bundled. This keeps the install small and the first frame fast.
- Weights: 400 and 600. No more than two weights on any screen.
- No all-caps labels, no letter-spaced "eyebrow" text.
- Icons: **Segoe Fluent Icons** (system font) or simple built-in vector shapes. No emoji, no sparkle, no decorative illustrations.

## 4. Layout and spacing

- 4 px base unit. Spacing scale: 4, 8, 12, 16, 24, 32, 48.
- Corner radius: 6 px for fields and buttons, 8 px for dialogs. No pill shapes except toggles.
- Minimum click target 32 x 32 px (40 px on the lock screen PIN pad).
- Left-aligned reading. No centered paragraphs. No decorative dividers.
- Manager window: left navigation list (Apps, Profiles, Security, Activity, Folders), one content area. No nested cards, no icon grids of equal-size tiles.
- Windows respect DPI (100% to 300%), multi-monitor, and RTL mirroring for Urdu (navigation moves to the right, text aligns right, PIN pad stays in normal digit order).

## 5. Screens

### 5.1 Lock screen (most important)
- A small, centered, topmost window over a dimmed screen; dim is a flat 55% black, no blur.
- Top to bottom: app icon (64 px), app name (28 px), one line: "Enter your PIN to open *App name*." Field or PIN pad. Primary button "Unlock". Secondary text links: "Use Windows Hello" (only if supported), "Forgot password?".
- Wrong attempt: field outline turns `danger`, a short shake (max 120 ms, skipped under reduced motion), and the text "Wrong PIN. 2 attempts left before a 30-second wait."
- Lockout: field disabled, text "Too many attempts. Try again in 0:27." with a live countdown.
- Esc closes the window and ends the app. State this in the cancel button text: "Cancel and close app".
- Focus starts in the field. Enter submits. Full keyboard use.

### 5.2 First-run wizard
Four steps, one decision per screen: 1) Create PIN or password, 2) Add recovery (Google/Microsoft email), 3) Save recovery codes (copy, print, or save), 4) Choose apps to lock. Show "Step 2 of 4", nothing else decorative. Each step can be revisited from Security settings.

### 5.3 Manager
- Apps: search field, list rows with icon, name, lock toggle, a mode summary ("Ask every time", "Grace 5 min"). Empty state: "No apps locked yet. Choose an app from the list."
- Security: change PIN/password, Windows Hello, recovery, intruder photo (with the plain sentence "Takes a photo with your camera after 3 wrong attempts. Saved only on this PC.").
- Activity: a simple table (time, event, app, result) with filter and "Clear log".
- Honest limits page under Security: a short, plain list of what AppLock cannot protect against.

## 6. Components (the full set; add nothing without need)

Button (primary, secondary, danger), text field, PIN pad, toggle, list row, dropdown, dialog, inline message (info, warning, error), navigation item, tooltip.

Every component defines all states: default, hover, focus (2 px `accent` ring with 2 px offset), pressed, disabled, error, loading, and empty where it applies.

## 7. Motion

- Only for state changes. Maximum 120 ms, ease-out. Nothing loops, bounces, or pulses.
- Everything is static when the system "reduce motion" setting is on.
- No loading spinners longer than needed; show text ("Checking...") for anything over 300 ms.

## 8. Writing and tone

Follows `antislop-copywriting`.

- Plain, short, factual sentences. Say what happened and what the user can do.
- No exclamation marks, no hype ("powerful", "seamless", "next-gen"), no emoji, no "Oops!".
- Errors: say what went wrong and the next step. "The PIN is wrong." not "Authentication failed due to invalid credentials."
- Buttons use verbs for the action: "Unlock", "Lock app", "Save recovery codes", "Cancel and close app".
- **Never invent numbers or claims.** No "military-grade", no "100% secure", no counts that the app did not measure.
- Quick Lock is always described as: "Hides the item and blocks normal access. It does not encrypt it."
- Every string exists in English and Urdu. Urdu is written by a natural-language translation, not word-by-word, and reviewed by a native speaker before release.

## 9. What antislop must catch in this project (checklist for the Delivery Gate)

- Sparkle/AI icons, "beta" or "NEW" pills, gradient or glow backgrounds
- Fake stats ("10,000 apps protected"), fake security badges, fake testimonials
- Equal-size card grids, centered hero text, decorative dividers
- Stock illustrations, mascots, emoji bullets
- Hype or vague copy, lorem ipsum, "Welcome to the future of..."
- Low-contrast gray text, missing focus ring, color-only state
- Comments that only restate the code
- Hard-coded colors or sizes outside `tokens.slint`

## 10. Change control

- Only the owner approves changes to this file. Agents may propose changes with a short reason and a before/after description.
- A change to tokens in this file is a `feat(ui)` or `chore(design)` PR that updates `ui/tokens.slint` in the same commit.
