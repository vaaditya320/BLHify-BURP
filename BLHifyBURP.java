import burp.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BLHifyBurp implements IBurpExtender, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private final Set<String> testedSocials = new HashSet<>();
    private final Set<String> reportedFindings = new HashSet<>();

    private static final Pattern SOCIAL_PATTERN = Pattern.compile(
            "(https?://(?:www\\.)?(?:twitter\\.com|x\\.com|instagram\\.com|facebook\\.com|tiktok\\.com)/[a-zA-Z0-9_./@-]+)",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("BLHify - Broken Social Link Scanner");
        callbacks.registerHttpListener(this);
        callbacks.printOutput("[+] BLHify loaded successfully");
        callbacks.printOutput("[+] Listening on all proxy traffic automatically");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) return;
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) return;

        byte[] response = messageInfo.getResponse();
        if (response == null) return;

        String body = new String(response);
        Matcher matcher = SOCIAL_PATTERN.matcher(body);

        while (matcher.find()) {
            String socialUrl = matcher.group(1);
            if (testedSocials.contains(socialUrl)) continue;
            testedSocials.add(socialUrl);

            callbacks.printOutput("[*] Checking: " + socialUrl);

            if (isBrokenSocial(socialUrl)) {
                String host = messageInfo.getHttpService().getHost();
                String key = host + "|" + socialUrl;
                if (reportedFindings.contains(key)) continue;
                reportedFindings.add(key);

                callbacks.printOutput("[!!!] BROKEN SOCIAL LINK: " + socialUrl);
                callbacks.addScanIssue(new BLHIssue(
                        messageInfo.getHttpService(),
                        helpers.analyzeRequest(messageInfo).getUrl(),
                        socialUrl
                ));
            } else {
                callbacks.printOutput("[-] Alive: " + socialUrl);
            }
        }
    }

    private boolean isBrokenSocial(String socialUrl) {
        try {
            String lower = socialUrl.toLowerCase();
            if (lower.contains("twitter.com") || lower.contains("x.com")) {
                return checkTwitter(socialUrl);
            } else if (lower.contains("instagram.com")) {
                return checkInstagram(socialUrl);
            } else if (lower.contains("facebook.com")) {
                return checkFacebook(socialUrl);
            } else if (lower.contains("tiktok.com")) {
                return checkTiktok(socialUrl);
            }
        } catch (Exception e) {
            callbacks.printOutput("    Error: " + e.getMessage());
        }
        return false;
    }

    // ===================== FACEBOOK =====================
    // Confirmed from Burp response: dead pages return JSON with:
    // "title": "This content isn't available at the moment"
    // "body": "When this happens, it's usually because..."
    // "__dr": "CometErrorRoot.react"
    // All inside a 200 response from /username endpoint
    private boolean checkFacebook(String socialUrl) {
        try {
            String fbUrl = socialUrl.replaceFirst("(?i)^https?://(?:www\\.)?facebook\\.com",
                    "https://www.facebook.com");
            callbacks.printOutput("    [FB] Fetching: " + fbUrl);

            HttpURLConnection conn = openConnection(fbUrl);
            int status = conn.getResponseCode();
            String finalUrl = conn.getURL().toString().toLowerCase();
            callbacks.printOutput("    [FB] Status: " + status + " | Final: " + finalUrl);

            // Redirect to login = definitely dead/private
            if (finalUrl.contains("/login") || finalUrl.contains("/r.php") ||
                finalUrl.contains("checkpoint")) {
                callbacks.printOutput("    [FB] -> Dead (redirected to login)");
                return true;
            }

            if (status == 404) {
                callbacks.printOutput("    [FB] -> Dead (404)");
                return true;
            }

            // Read full body - Facebook embeds error in JSON inside the HTML
            String body = readFullBody(conn);
            callbacks.printOutput("    [FB] Body length: " + body.length());

            // CONFIRMED exact strings from Burp intercept
            if (body.contains("This content isn't available at the moment") ||
                body.contains("This content isn\u2019t available at the moment") ||
                body.contains("CometErrorRoot.react") ||
                body.contains("\"title\":\"This content") ||
                body.contains("isAdminViewingDeactivatedProfile") ||  // appears in dead profile JSON
                body.contains("PageNotFound") ||
                body.contains("page_not_found") ||
                body.contains("\"__type\":404") ||
                body.contains("contentNotFound")) {
                callbacks.printOutput("    [FB] -> Dead (confirmed error in JSON response)");
                return true;
            }

        } catch (Exception e) {
            callbacks.printOutput("    [FB] Error: " + e.getMessage());
        }
        return false;
    }

    // ===================== INSTAGRAM =====================
    // Instagram raw HTML DOES contain the error message (confirmed from screenshot)
    // "Sorry, this page isn't available."
    // "The link you followed may be broken, or the page may have been removed."
    private boolean checkInstagram(String socialUrl) {
        try {
            String igUrl = socialUrl.replaceFirst("(?i)^https?://(?:www\\.)?instagram\\.com",
                    "https://www.instagram.com");
            callbacks.printOutput("    [IG] Fetching: " + igUrl);

            HttpURLConnection conn = openConnection(igUrl);
            int status = conn.getResponseCode();
            String finalUrl = conn.getURL().toString().toLowerCase();
            callbacks.printOutput("    [IG] Status: " + status + " | Final: " + finalUrl);

            if (status == 404) {
                callbacks.printOutput("    [IG] -> Dead (404)");
                return true;
            }

            if (finalUrl.contains("/accounts/login") || finalUrl.contains("/challenge/")) {
                callbacks.printOutput("    [IG] -> Dead (redirected to login)");
                return true;
            }

            String body = readFullBody(conn);
            callbacks.printOutput("    [IG] Body length: " + body.length());

            // Confirmed from screenshot - these strings appear in raw HTML
            if (body.contains("Sorry, this page isn") ||
                body.contains("Sorry, this page isn\u2019t available") ||
                body.contains("The link you followed may be broken") ||
                body.contains("page may have been removed") ||
                body.contains("Go back to Instagram")) {
                callbacks.printOutput("    [IG] -> Dead (error message found in HTML)");
                return true;
            }

            // Fallback: og:title check - dead page = "Instagram" only
            Pattern ogTitle = Pattern.compile(
                    "og:title\"[^>]*content=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
            Matcher m = ogTitle.matcher(body);
            if (m.find()) {
                String title = m.group(1).trim();
                callbacks.printOutput("    [IG] og:title = " + title);
                if (title.equalsIgnoreCase("instagram") || !title.contains("@")) {
                    callbacks.printOutput("    [IG] -> Dead (generic og:title)");
                    return true;
                }
            }

        } catch (Exception e) {
            callbacks.printOutput("    [IG] Error: " + e.getMessage());
        }
        return false;
    }

    // ===================== TWITTER / X =====================
    // X is fully JS rendered - raw HTML won't have the error message
    // Best signals available without JS execution:
    // 1. Redirect to login page
    // 2. og:title = "X" with no @handle (dead account)
    // 3. "UserUnavailable" in embedded JS data
    // 4. Handle not present anywhere in source
    private boolean checkTwitter(String socialUrl) {
        try {
            String xUrl = socialUrl.replaceFirst("(?i)twitter\\.com", "x.com");
            callbacks.printOutput("    [X] Fetching: " + xUrl);

            HttpURLConnection conn = openConnection(xUrl);
            int status = conn.getResponseCode();
            String finalUrl = conn.getURL().toString().toLowerCase();
            callbacks.printOutput("    [X] Status: " + status + " | Final: " + finalUrl);

            if (finalUrl.contains("/i/flow/login") || finalUrl.contains("/account/access")) {
                callbacks.printOutput("    [X] -> Dead (redirected to login)");
                return true;
            }

            if (status == 404) {
                callbacks.printOutput("    [X] -> Dead (404)");
                return true;
            }

            String body = readFullBody(conn);
            callbacks.printOutput("    [X] Body length: " + body.length());

            // Check for embedded JS data markers
            if (body.contains("\"UserUnavailable\"") ||
                body.contains("userUnavailable") ||
                body.contains("this account doesn") ||
                body.contains("This account doesn")) {
                callbacks.printOutput("    [X] -> Dead (UserUnavailable in source)");
                return true;
            }

            // og:title check: dead = "X", live = "Name (@handle) / X"
            Pattern ogTitle = Pattern.compile(
                    "og:title\"[^>]*content=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
            Matcher m = ogTitle.matcher(body);
            if (m.find()) {
                String title = m.group(1).trim();
                callbacks.printOutput("    [X] og:title = " + title);
                if (title.equalsIgnoreCase("x") || !title.contains("@")) {
                    callbacks.printOutput("    [X] -> Dead (og:title has no @handle)");
                    return true;
                }
            } else {
                // No og:title found - check if handle appears anywhere in source
                String handle = extractHandle(socialUrl).toLowerCase();
                callbacks.printOutput("    [X] No og:title found, checking for handle: " + handle);
                if (!handle.isEmpty() && !body.toLowerCase().contains(handle)) {
                    callbacks.printOutput("    [X] -> Dead (handle not found in source)");
                    return true;
                }
            }

        } catch (Exception e) {
            callbacks.printOutput("    [X] Error: " + e.getMessage());
        }
        return false;
    }

    // ===================== TIKTOK =====================
    // TikTok returns 404 for dead accounts or embeds user_not_found in JSON
    private boolean checkTiktok(String socialUrl) {
        try {
            callbacks.printOutput("    [TT] Fetching: " + socialUrl);

            HttpURLConnection conn = openConnection(socialUrl);
            int status = conn.getResponseCode();
            callbacks.printOutput("    [TT] Status: " + status);

            if (status == 404) {
                callbacks.printOutput("    [TT] -> Dead (404)");
                return true;
            }

            String body = readFullBody(conn);
            callbacks.printOutput("    [TT] Body length: " + body.length());

            if (body.contains("couldn't find this account") ||
                body.contains("Couldn\u2019t find this account") ||
                body.contains("user not found") ||
                body.contains("\"statusCode\":10202") ||
                body.contains("\"message\":\"user_not_found\"")) {
                callbacks.printOutput("    [TT] -> Dead (user not found)");
                return true;
            }

            // og:title check: dead = "TikTok" only
            Pattern ogTitle = Pattern.compile(
                    "og:title\"[^>]*content=\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
            Matcher m = ogTitle.matcher(body);
            if (m.find()) {
                String title = m.group(1).trim();
                callbacks.printOutput("    [TT] og:title = " + title);
                if (title.equalsIgnoreCase("tiktok") || !title.contains("@")) {
                    callbacks.printOutput("    [TT] -> Dead (generic og:title)");
                    return true;
                }
            }

        } catch (Exception e) {
            callbacks.printOutput("    [TT] Error: " + e.getMessage());
        }
        return false;
    }

    private String extractHandle(String socialUrl) {
        try {
            String path = new URI(socialUrl).getPath();
            return path.replaceAll("^/+", "").split("/")[0].replace("@", "");
        } catch (Exception e) {
            return "";
        }
    }

    private HttpURLConnection openConnection(String urlStr) throws Exception {
        URL url = new URI(urlStr).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setRequestProperty("User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
        conn.setRequestProperty("Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        conn.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
        conn.setRequestProperty("Accept-Encoding", "identity"); // plain text, no gzip
        conn.setRequestProperty("Cache-Control", "no-cache");
        return conn;
    }

    // Read entire body (no line limit - we need full FB JSON)
    private String readFullBody(HttpURLConnection conn) throws Exception {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        } catch (Exception e) {
            if (conn.getErrorStream() != null) {
                reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
            } else {
                return "";
            }
        }

        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }

    // === CUSTOM ISSUE CLASS ===
    static class BLHIssue implements IScanIssue {

        private final IHttpService service;
        private final URL pageUrl;
        private final String socialUrl;

        BLHIssue(IHttpService service, URL pageUrl, String socialUrl) {
            this.service = service;
            this.pageUrl = pageUrl;
            this.socialUrl = socialUrl;
        }

        @Override public URL getUrl() { return pageUrl; }
        @Override public String getIssueName() { return "Broken Social Link Hijack"; }
        @Override public int getIssueType() { return 0x08000000; }
        @Override public String getSeverity() { return "Low"; }
        @Override public String getConfidence() { return "Firm"; }

        @Override
        public String getIssueBackground() {
            return "Broken social media links may allow attackers to register the missing account and impersonate the organization.";
        }

        @Override
        public String getRemediationBackground() {
            return "Ensure all social links point to valid accounts or remove them if unused.";
        }

        @Override
        public String getIssueDetail() {
            return "The page contains a broken social media link:<br><br>"
                    + "<b>" + socialUrl + "</b><br><br>"
                    + "An attacker may claim this handle and impersonate the brand.";
        }

        @Override public String getRemediationDetail() { return null; }
        @Override public IHttpRequestResponse[] getHttpMessages() { return null; }
        @Override public IHttpService getHttpService() { return service; }
        @Override public String getProtocol() { return service.getProtocol(); }
        @Override public int getPort() { return service.getPort(); }
        @Override public String getHost() { return service.getHost(); }
    }
}