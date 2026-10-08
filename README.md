# BLHify-BURP

A native Java Burp extension for discovering social links and checking Facebook, Instagram, and X profiles. No Node server, third-party checker service, API key, or Python runtime is needed to run the extension. The supplied `index.js`, `insta.js`, and `x.js` remain reference implementations.

## Build and install

Requires a JDK 17+ with `java`, `javac`, and `jar`, and Windows PowerShell. From the repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Test
```

This downloads the pinned Burp Extender API 2.3 and Gson 2.11.0 from Maven Central on the first build, compiles Java 17 bytecode, runs the offline tests, and creates **BLHify.jar**. Gson is bundled; Burp supplies its own API classes. Later builds work offline with the cached `lib` dependencies. Omit `-Test` to build only. `python make.py --test` is an optional wrapper for the same build.

In Burp, open **Extensions → Add → Java**, select `BLHify.jar`, and open the **BLHify** tab. The extension uses the standard `burp.BurpExtender` entry point and Burp's [legacy extension API](https://portswigger.net/burp/extender/api/).

## Use the BLHify tab

1. Browse the target through Burp Proxy. HTML discovery uses actual anchor hyperlinks and excludes script/style content and comments. Other text, JSON, JavaScript and XML responses are inspected for profile URLs in background workers. Responses from the social platforms themselves (including their subdomains and known CDN domains) are excluded, so visiting Instagram does not import its navigation into your target's inventory.
2. The table shows each normalized social link, platform, status, page count, reason, and last check time. Select a row to see its source-page URLs and original link spelling.
3. Search by URL, source page, platform or reason; filter by status; select rows for a recheck.
4. Turn off **Auto-check new links** for manual checking. **Check pending / unknown** checks collected profiles that still need a result. Turning off auto-check does not cancel already queued work.
5. **In-scope pages only** limits future discovery to Burp target scope. **Capture proxy traffic** controls future collection. The default captures all proxy responses and automatically checks newly discovered profiles.
6. Export CSV to retain the inventory (one row per normalized link/source-page pair). Inventory is session-only. **Clear** resets the tab and pending checks; existing Burp issues remain. An already running request may finish, but its result cannot repopulate the cleared inventory.

Links using `twitter.com`/`x.com`, mobile/www hosts, profile capitalization, trailing slashes, and profile tracking queries are deduplicated. Each distinct source-page URL is retained. If multiple aliases appear on the same page, the first original spelling is shown. HTTP, HTTPS, protocol-relative and JSON-escaped social URLs are recognized. The extension records the five known social domains; it is not a crawler or a JavaScript browser and does not enumerate arbitrary social services.

Only username-profile candidates on Facebook, Instagram and X enter the inventory. Platform homepages (including language/query variants), post URLs, sharing/tracking endpoints, reserved platform routes, Facebook numeric `profile.php?id=...` links, and TikTok links are excluded. A candidate URL is not proof that its handle is available to register.

## Native checking logic

| Platform | Requests and interpretation |
| --- | --- |
| Facebook | GET the profile, preserve anonymous cookies, extract the LSD token and available page parameters, then POST to Facebook's `/ajax/bulk-route-definitions/`. Profile/page routes mean EXISTS; an error route means UNAVAILABLE unless it signals privacy restriction or deactivation. Unexpected routes and malformed payloads mean UNKNOWN. |
| Instagram | The equivalent GET/token/cookie/POST flow uses Instagram-specific headers and `__comet_req=7`. The requested route's boolean `error=false` means EXISTS and `error=true` means UNAVAILABLE. `pageID=ProfilePage` is a positive fallback. When route parsing fails or the token is missing, an independent native request to Instagram's `api/v1/users/web_profile_info/` is attempted. A successful response identifying the exact username means EXISTS; successful JSON with `data.user=null` means UNAVAILABLE. Generic HTML errors, rejected requests, and rate limits remain UNKNOWN. |
| X | GET the profile and inspect HTTP status, title and Open Graph title. Not-found responses mean UNAVAILABLE; a title identifying the exact handle means EXISTS; suspension has its own status. A generic app shell or `noindex` alone means UNKNOWN. |

These checks port the reference scripts' platform requests, with deliberate corrections to avoid classifying parsing errors, login redirects, generic HTML, or network failures as missing accounts. Fresh extracted parameters are used instead of hardcoded revision values, and `jazoest` is derived from the current LSD token.

**UNAVAILABLE does not mean claimable.** Only unavailable results create informational, tentative Burp issues, deduplicated by social profile and source page. Issues contain the source URL and check reason; raw source/check request-response attachments are not retained. Private, restricted, suspended, deleted and renamed profiles can require manual investigation.

## Network behavior and limits

- Direct anonymous Java HTTPS requests contact the platforms themselves. They do not use your browser's authenticated cookies, Burp's session-handling rules, upstream proxy configuration, or Burp HTTP history. No tokens or cookies are printed to the activity log.
- Two check workers, a bounded 200-job queue and a one-second pause per worker keep checks off the proxy/UI threads. HTTP 429 starts a two-minute platform cooldown; affected jobs become UNKNOWN and can be retried manually.
- Connect/read timeouts are 10 seconds; body reading has a 20-second deadline. Response bodies are capped at 4 MiB. Up to five redirects are allowed on the original HTTPS host; off-host redirects become UNKNOWN.
- Gzip and deflate are decoded. Captured responses with other content encodings, binary MIME types, wire sizes above 8 MiB or decoded sizes above 4 MiB are skipped.
- Collection limits: 10,000 links, 500 pages per link, 50,000 total link/page associations, and 500 distinct extracted spellings per response. Busy discovery/UI queues may skip responses and log that event. Export and clear between large engagements.
- Platform routes are undocumented and may change. Login requirements, bot protection, rate limits and network location can prevent a conclusive anonymous check.

## Verification

`build.ps1 -Test` checks URL normalization, false-positive regressions, Facebook/Instagram request construction and route parsing, X signals, native cookie reuse/gzip/redirect handling against a local HTTP server, mocked Burp registration/discovery, multiple source pages, issue deduplication, and unload cleanup. It also renders a headless Swing preview to `build/ui-preview.png`.

The suite does not require live platform access. A separate optional smoke test can be run after building:

```powershell
javac --release 17 -cp 'BLHify.jar;lib/burp-extender-api-2.3.jar' -d build/classes tests/LiveSmoke.java
java -cp 'BLHify.jar;build/classes;lib/burp-extender-api-2.3.jar' burp.LiveSmoke https://www.facebook.com/facebook https://www.instagram.com/instagram/ https://x.com/x
```

During development, X returned identifiable profile data and Facebook returned HTTP 400. Investigation of Instagram's `xk9z_qlmfp_idealab_zz99` test handle versus its existing `instagram` account found the same HTTP-200 `httpErrorPage` for both. Their route requests returned error **1357054** with a null payload, and their independent profile requests returned **HTTP 429**. These responses cannot distinguish the accounts. The extension now retains those concrete failure reasons instead of replacing them with the generic HTML fallback. Native requests still depend on Instagram accepting requests from the current environment; no successful live missing-account classification is claimed for that test handle. The user has confirmed that the JAR loads in Burp; automated UI and callback verification uses the test harness.
