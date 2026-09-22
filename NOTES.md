# Notes

Working notes, not documentation. Two lists: what James has to do by hand, and what the API side still needs before the plugin can be measured.

## James, by hand

1. **Create the public repo.** `jamesdfinance-dev/lazaretto-plugins`, public, and push this tree to `main`. `/plugin marketplace add jamesdfinance-dev/lazaretto-plugins` reads `.claude-plugin/marketplace.json` from the default branch, so nothing else is needed for the self-hosted route and there is no review queue.

2. **Pick the slug before you submit, not after.** The plugin name `lazaretto-guard` is what the Console form registers and it is immutable after publication. It is the id people type in `/plugin install lazaretto-guard@...` forever. The directory name, `plugin.json` `name`, and the marketplace entry `name` all have to agree, so changing your mind later means a second plugin, not a rename.

3. **Submit at the Console form**, platform.claude.com/plugins/submit. The bar is `claude plugin validate` plus automated safety screening, both of which this passes today. The official marketplace is curated with no application process, so that is not the target. Approved plugins get pinned to a commit SHA with CI bumping the pin, which is why `plugin.json` carries an explicit version: a pin bump must not be able to ship an unreviewed commit under the same version number.

4. **Version discipline.** `plugins/lazaretto-guard/.claude-plugin/plugin.json` and the `lazaretto-plugins` marketplace entry both say `0.1.0`. Bump them together. `claude plugin tag` validates that they agree and cuts the `lazaretto-guard--v0.1.0` tag.

5. **Verify a first install from a clean machine**, not from this checkout. The cheapest real test is the one in INSTALL.md: ask an agent to install a version named on https://lazaretto.dev/caught and confirm a permission prompt with advisory ids appears, then confirm a clean install produces no prompt. It will not be free of delay: expect the hook to add up to about 1.5 seconds before the command runs, nearer a second on a warm answer. Time it, because that number is what people will decide to keep or remove the plugin over.

## What the API side still needs

None of this is in the API repo yet. Nothing here was changed in `/Users/jamesdykstra/Documents/lazaretto`.

1. **Count guard hook fires separately.** The hook already sends `user-agent: lazaretto-guard/<version>` and `x-lazaretto-client: lazaretto-guard/<version>` on every `POST /check`. Nothing reads either header today, so guard traffic is currently indistinguishable from curl traffic in the funnel. Add a `FunnelEventName` of `guard_hook_fire` in `src/api/funnel-events.ts` and record it from `POST /check` when that header is present, with the version as the detail.

2. **Count ask decisions.** No second request is needed. A hook fire whose result has a non-empty `malicious` list is exactly an ask, because that is the only branch where the hook prints anything. Record `guard_ask` on that branch of the same request.

3. **Ask acceptances are not measurable yet, and that is the metric that matters.** The hook cannot report an acceptance, because PreToolUse returns before the person decides. It needs a keyless, names-only endpoint, for example `POST /v1/guard/event` taking `{"event":"ask_accepted"}` and nothing else, recorded through `recordEvent` like every other funnel event. Once that exists, the plugin adds a `PostToolUse` hook on Bash that reports an acceptance when the command it asked about then ran. That hook is deliberately not in this repo: shipping a call to an endpoint that does not exist is dead code on every user's machine.

4. **Name the client carefully.** `isCrawler` in `src/api/app.ts` flags any user agent matching `/bot\b|crawler|spider|crawl|.../`. A client string containing "bot" would file every hook fire as a crawler and drop it out of the funnel it is meant to appear in. `lazaretto-guard/<version>` is clear of that list. Do not rename it to something like `lazaretto-guard-bot`.

5. **`/check` renders for a terminal, so the hook parses text.** It reads the `KNOWN MALWARE` block by matching lines against the specs it sent, rather than by column position, because the route's padding collapses to nothing for refs longer than 46 characters and a layout parser would read those lines wrong. There is a test for exactly that case. Matching by ref needs a boundary after it, or `chalk@5.6.1` matches the line for `chalk@5.6.10` and a clean package is reported as a hit: whitespace, end of line, or the uppercase letter that starts an advisory id, since the collision case leaves no gap. That has its own test too, in both directions. It would be cleaner if `POST /check` honoured `accept: application/json` and returned the `/v1/lockfile` shape. The hook already reads that shape, so the day the route offers it nothing in the plugin has to change. Until then, a change to `checkResultText` in `src/api/check-text.ts` can break the hook silently, which is the one coupling worth a test on the API side.

6. **`POST /check` is too slow for a 2 second hook, in two of the five calls ever measured.** Measured from this machine on 2026-09-22, five consecutive calls with one package: 1047ms, 2617ms, 2580ms, 988ms, 981ms. That is the whole sample, so read the drop rate as two of five and not as a percentage anyone should quote. The hook declares a 2 second timeout and must return inside it, so it aborts at 1.45 seconds. Both of those 2.6 second answers would have been dropped, silently, and a dropped answer looks exactly like a clean one. The same five numbers are in the README, with the same date on them. This is the single biggest thing limiting how often the hook can actually warn anyone, and it is entirely on the API side. Worth finding out whether the tail is Fly cold start, TLS, or the feed lookup itself, because a cheap identity-only route that answers in 200ms would change the hook from half useful to reliable. Do not solve it by raising the hook timeout: a hook that can hold an install for 3 seconds is a hook people remove.

7. **The rate limit is already fine.** The plan said to raise `LOCKFILE_PER_MIN` above 10 first. It is already 60 in `src/config.ts`, raised for exactly this reason. Nothing to do.

8. **No paid prompt on this path, and the API must keep it that way.** The hook never renders the trailing section of the `/check` text, so the free-trial line at the bottom of `checkResultText` never reaches a user through the plugin. If a paywall or a payment hint ever moves into the `KNOWN MALWARE` block itself, it would end up in a permission prompt, and a prompt that blocks and then sells is the thing this design is built to avoid.

## Not done here, on purpose

No GitHub repository was created, nothing was pushed, and nothing was submitted anywhere. The API repo was read and not modified.

## Not verified

Verified: the manifests pass `claude plugin validate --strict`. The hook process was run by hand against the live API with a real hook input and produced the ask payload, with `debug@4.4.2` coming back as `MAL-2025-46974`, in about 1.05 seconds. The 53 tests pass.

Not verified: the plugin has never been installed into a Claude Code session, so `hooks/hooks.json` has not been loaded by the thing that reads it. Its structure copies a plugin already shipping in the official marketplace, field for field, but that is inference, not a live fire. Two specific things to watch on the first real install:

- whether the `Write|Edit|MultiEdit` matcher fires the way the `Bash` one does. The Bash path is the one with real precedent in the marketplace.
- whether a 2 second hook timeout shows up in the UI as a timeout when it is hit, or passes quietly. The hook is built to never reach it, but the failure mode matters.
