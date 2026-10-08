package burp;

import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

/** Native, anonymous requests to the social platforms; no checker service. */
final class SocialChecker {
    enum Status { DISCOVERED, QUEUED, CHECKING, EXISTS, UNAVAILABLE, SUSPENDED, UNKNOWN, UNSUPPORTED }
    static final class Result {
        final Status status;
        final String reason;
        Result(Status status, String reason) { this.status = status; this.reason = reason; }
    }
    static Result result(Status status, String reason) { return new Result(status, reason); }
    static final class Profile {
        final String platform, handle, url;
        final boolean supported;
        Profile(String platform, String handle, String url, boolean supported) {
            this.platform = platform; this.handle = handle; this.url = url; this.supported = supported;
        }
    }
    private static final Set<String> RESERVED = new HashSet<>(Arrays.asList(
        "login", "logout", "signup", "register", "accounts", "challenge", "checkpoint", "help", "about",
        "privacy", "terms", "policies", "legal", "explore", "search", "intent", "share", "sharer",
        "sharer.php", "dialog", "plugins", "reel", "reels", "p", "tv", "stories", "direct", "i",
        "home", "notifications", "messages", "settings", "hashtag", "watch", "groups", "events",
        "marketplace", "photo.php", "photos", "videos", "pages", "profile.php", "l.php", "r.php",
        "tr", "ajax", "api", "graphql", "static", "web", "download", "developer", "developers", "business"));
    static boolean socialHost(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        for (String domain : Arrays.asList("facebook.com","instagram.com","twitter.com","x.com","tiktok.com","fbcdn.net","cdninstagram.com"))
            if (lower.equals(domain) || lower.endsWith("." + domain)) return true;
        return false;
    }
    static final Pattern LINKS = Pattern.compile(
        "(?i)(?<![a-z0-9/])(?:https?:)?//(?:(?:www|m|mbasic)\\.)?(?:facebook\\.com|instagram\\.com|twitter\\.com|x\\.com|tiktok\\.com)(?=[/\\s\"'<>]|$)[^\\s\"'<>\\\\]*");

    static Profile profile(String raw) {
        try {
            String value = raw.replace("&amp;", "&").replaceAll("[),;]+$", "");
            URI uri = URI.create(value.startsWith("//") ? "https:" + value : value);
            if (uri.getUserInfo() != null || uri.getPort() != -1) return null;
            String host = uri.getHost().toLowerCase(Locale.ROOT).replaceFirst("^(www|m|mbasic)\\.", "");
            String platform = host.equals("facebook.com") ? "Facebook" : host.equals("instagram.com") ? "Instagram"
                : host.equals("x.com") || host.equals("twitter.com") ? "X" : host.equals("tiktok.com") ? "TikTok" : null;
            if (platform == null) return null;
            String path = uri.getPath() == null ? "" : uri.getPath();
            String[] parts = path.replaceFirst("^/", "").split("/");
            String handle = parts.length == 0 ? "" : parts[0].toLowerCase(Locale.ROOT);
            boolean supported = !platform.equals("TikTok") && parts.length == 1 && !RESERVED.contains(handle)
                && handle.matches(platform.equals("X") ? "[a-z0-9_]{1,15}" : platform.equals("Instagram") ? "[a-z0-9._]{1,30}" : "[a-z0-9._-]{1,60}");
            String canonicalHost = platform.equals("X") ? "x.com" : "www." + host;
            String canonical = "https://" + canonicalHost + (supported ? "/" + handle + (platform.equals("Instagram") ? "/" : "") : path)
                + (!supported && uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");
            return new Profile(platform, handle, canonical, supported);
        } catch (RuntimeException e) { return null; }
    }
    static String decodedLinks(String text) {
        return text.replace("\\/", "/").replace("\\u002F", "/").replace("\\u002f", "/").replace("&amp;", "&");
    }

    interface Transport { Reply send(String url, String body, Map<String,String> headers) throws Exception; }
    static final class Reply {
        final int code;
        final String url, body;
        Reply(int code, String url, String body) { this.code = code; this.url = url; this.body = body; }
    }
    static final class NativeTransport implements Transport {
        final CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER);
        @Override public Reply send(String url, String body, Map<String,String> headers) throws Exception {
            URI uri = URI.create(url);
            String originalHost = uri.getHost();
            for (int redirect = 0; redirect <= 5; redirect++) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
                connection.setConnectTimeout(10000); connection.setReadTimeout(10000);
                connection.setInstanceFollowRedirects(false);
                try {
                    connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
                    connection.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
                    connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
                    connection.setRequestProperty("Accept-Encoding", "gzip, deflate");
                    connection.setRequestProperty("Sec-Ch-Ua", "\"Chromium\";v=\"122\", \"Google Chrome\";v=\"122\"");
                    connection.setRequestProperty("Sec-Ch-Ua-Mobile", "?0");
                    connection.setRequestProperty("Sec-Ch-Ua-Platform", "\"Windows\"");
                    for (Map.Entry<String,String> h : headers.entrySet()) connection.setRequestProperty(h.getKey(), h.getValue());
                    for (Map.Entry<String,List<String>> h : cookies.get(uri, Collections.emptyMap()).entrySet())
                        connection.setRequestProperty(h.getKey(), String.join("; ", h.getValue()));
                    if (body != null) {
                        connection.setRequestMethod("POST"); connection.setDoOutput(true);
                        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                        try (OutputStream out = connection.getOutputStream()) { out.write(body.getBytes(StandardCharsets.UTF_8)); }
                    }
                    int code = connection.getResponseCode();
                    cookies.put(uri, connection.getHeaderFields());
                    if (Arrays.asList(301,302,303,307,308).contains(code)) {
                        String location = connection.getHeaderField("Location");
                        if (location == null) throw new IOException("Redirect without Location");
                        URI next = uri.resolve(location);
                        // Do not forward tokens/cookies to arbitrary destinations or downgrade TLS.
                        if (!"https".equals(next.getScheme()) || !originalHost.equalsIgnoreCase(next.getHost()) || next.getUserInfo() != null || next.getPort() != -1)
                            throw new IOException("Redirect outside the original HTTPS host");
                        if (code == 303 || ((code == 301 || code == 302) && body != null)) body = null;
                        uri = next; continue;
                    }
                    InputStream input = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
                    if (input == null) return new Reply(code, uri.toString(), "");
                    String encoding = connection.getContentEncoding();
                    if ("gzip".equalsIgnoreCase(encoding)) input = new GZIPInputStream(input);
                    else if ("deflate".equalsIgnoreCase(encoding)) input = new InflaterInputStream(input);
                    else if (encoding != null && !"identity".equalsIgnoreCase(encoding)) throw new IOException("Unsupported content encoding");
                    try (InputStream in = input; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                        byte[] buffer = new byte[8192]; int count;
                        long deadline = System.nanoTime() + 20_000_000_000L;
                        while ((count = in.read(buffer)) != -1) {
                            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                            if (System.nanoTime() > deadline) throw new IOException("Response deadline exceeded");
                            if (out.size() + count > 4 * 1024 * 1024) throw new IOException("Response exceeds 4 MiB limit");
                            out.write(buffer, 0, count);
                        }
                        return new Reply(code, uri.toString(), out.toString(StandardCharsets.UTF_8.name()));
                    }
                } finally { connection.disconnect(); }
            }
            throw new IOException("Too many redirects");
        }
    }
    Result check(Profile profile) { return check(profile, new NativeTransport()); }
    Result check(Profile profile, Transport transport) {
        if (!profile.supported) return result(Status.UNSUPPORTED, "Recorded link; only Facebook, Instagram and X profile URLs can be checked.");
        try {
            Map<String,String> headers = new LinkedHashMap<>();
            headers.put("Sec-Fetch-Site", "none"); headers.put("Sec-Fetch-Mode", "navigate"); headers.put("Sec-Fetch-Dest", "document");
            Reply page = transport.send(profile.url, null, headers);
            Result blocked = blocked(page);
            if (blocked != null) return blocked;
            if (profile.platform.equals("X")) return parseX(page, profile.handle);
            boolean ig = profile.platform.equals("Instagram");
            Result html = ig ? instagramHtml(page.body) : null;
            String lsd = first(page.body, "\"LSD\"\\s*,\\s*\\[\\]\\s*,\\s*\\{\\s*\"token\"\\s*:\\s*\"([^\"]+)\"",
                "\"(?:lsd|X-FB-LSD)\"\\s*:\\s*\"([^\"]+)\"", "name=[\"']lsd[\"']\\s+value=[\"']([^\"']+)");
            if (lsd.isEmpty()) {
                Result missing = html != null ? html : result(Status.UNKNOWN, "Profile response has no LSD token or conclusive account signal (HTTP " + page.code + ").");
                return ig && missing.status == Status.UNKNOWN ? instagramFallback(profile,transport,missing) : missing;
            }
            String origin = ig ? "https://www.instagram.com" : "https://www.facebook.com";
            Map<String,String> form = new LinkedHashMap<>();
            form.put("route_urls[0]", "/" + profile.handle); form.put("__user", "0"); form.put("__a", "1");
            form.put("__req", ig ? "2" : "3"); form.put("dpr", "1"); form.put("__ccg", ig ? "GOOD" : "EXCELLENT");
            form.put("__comet_req", ig ? "7" : "15"); form.put("lsd", lsd);
            // jazoest is derived from the current token rather than a stale captured value.
            int sum = 0; for (char c : lsd.toCharArray()) sum += c;
            form.put("jazoest", "2" + sum);
            for (String key : Arrays.asList("__spin_r", "__spin_t", "__hsi", "__rev", "__spin_b", "__hs")) {
                String value = first(page.body, "\"" + key + "\"\\s*:\\s*\"([^\"]+)\"", "\"" + key + "\"\\s*:\\s*(\\d+)");
                if (!value.isEmpty()) form.put(key, value);
            }
            if (ig) form.put("__d", "www");
            headers.put("Origin", origin); headers.put("Referer", profile.url); headers.put("X-FB-LSD", lsd);
            headers.put("X-ASBD-ID", "359341"); headers.put("Accept", "*/*");
            headers.put("Sec-Fetch-Site", "same-origin"); headers.put("Sec-Fetch-Mode", "cors"); headers.put("Sec-Fetch-Dest", "empty");
            if (ig) { headers.put("X-IG-D", "www"); headers.put("X-IG-Max-Touch-Points", "10"); }
            StringJoiner encoded = new StringJoiner("&");
            for (Map.Entry<String,String> e : form.entrySet()) encoded.add(URLEncoder.encode(e.getKey(), "UTF-8") + "=" + URLEncoder.encode(e.getValue(), "UTF-8"));
            Reply route = transport.send(origin + "/ajax/bulk-route-definitions/", encoded.toString(), headers);
            blocked = blocked(route);
            if (blocked != null) return blocked;
            if (route.code != 200) return result(Status.UNKNOWN, "Route endpoint returned HTTP " + route.code);
            Result parsed = parseRoute(route.body, profile.handle, ig);
            if (parsed.status != Status.UNKNOWN) return parsed;
            if (html != null && html.status == Status.EXISTS) return html;
            return ig ? instagramFallback(profile,transport,parsed) : parsed;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); return result(Status.UNKNOWN, "Check cancelled.");
        } catch (Exception e) { return result(Status.UNKNOWN, "Check failed: " + e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }
    private Result instagramFallback(Profile profile, Transport transport, Result previous) throws Exception {
        Map<String,String> headers = new LinkedHashMap<>();
        headers.put("X-IG-App-ID","936619743392459");
        headers.put("Accept","application/json");
        headers.put("Referer",profile.url);
        Reply reply = transport.send("https://www.instagram.com/api/v1/users/web_profile_info/?username=" + profile.handle,null,headers);
        Result result = parseInstagramProfile(reply,profile.handle);
        return result.status == Status.UNKNOWN ? result(Status.UNKNOWN,previous.reason + " Profile lookup: " + result.reason) : result;
    }
    static Result parseInstagramProfile(Reply reply, String handle) {
        Result blocked = blocked(reply); if (blocked != null) return blocked;
        try {
            JsonObject json = JsonParser.parseString(reply.body).getAsJsonObject();
            if (!json.has("status") || !"ok".equals(json.get("status").getAsString()))
                return result(Status.UNKNOWN,"Instagram did not return a successful profile lookup (HTTP " + reply.code + ").");
            JsonObject data = json.getAsJsonObject("data");
            if (reply.code == 200 && data != null && data.has("user")) {
                JsonElement user = data.get("user");
                if (user.isJsonNull()) return result(Status.UNAVAILABLE,"Instagram profile lookup succeeded with data.user=null for the requested username; claimability is unverified.");
                if (user.isJsonObject() && user.getAsJsonObject().has("username")
                        && handle.equalsIgnoreCase(user.getAsJsonObject().get("username").getAsString()))
                    return result(Status.EXISTS,"Instagram profile lookup identified @" + handle + ".");
            }
            return result(Status.UNKNOWN,"Profile lookup did not identify the requested username.");
        } catch (RuntimeException e) { return result(Status.UNKNOWN,"Profile lookup returned no usable JSON (HTTP " + reply.code + ")."); }
    }
    static Result blocked(Reply response) {
        String path = URI.create(response.url).getPath().toLowerCase(Locale.ROOT);
        if (path.matches(".*(?:/login|/checkpoint|/challenge|/accounts/|/i/flow/|/account/access|/consent).*"))
            return result(Status.UNKNOWN, "Login, consent or challenge redirect; account existence is unknown.");
        if (response.code == 429) return result(Status.UNKNOWN, "Rate limited (HTTP 429); retry later.");
        if (response.code == 401 || response.code == 403 || response.code >= 500)
            return result(Status.UNKNOWN, "Blocked or upstream failure (HTTP " + response.code + ").");
        if (response.code != 200 && response.code != 404 && response.code != 410)
            return result(Status.UNKNOWN, "Unexpected HTTP " + response.code);
        String lower = response.body.toLowerCase(Locale.ROOT);
        if (lower.contains("<title>just a moment") || lower.contains("<title>access denied") || lower.contains("<title>log in")
                || lower.contains("<title>login") || lower.contains("<title>challenge") || lower.contains("<title>verify"))
            return result(Status.UNKNOWN, "Login or anti-bot page; account existence is unknown.");
        return null;
    }
    static Result instagramHtml(String html) {
        String pageId = first(html, "\"pageID\"\\s*:\\s*\"([^\"]+)\"");
        if (pageId.equals("httpErrorPage")) return result(Status.UNKNOWN, "Instagram returned a generic httpErrorPage; this also occurs for existing accounts. Route confirmation is required.");
        if (pageId.equals("ProfilePage")) return result(Status.EXISTS, "Instagram pageID=ProfilePage.");
        return null;
    }
    static Result parseRoute(String raw, String handle, boolean instagram) {
        try {
            JsonObject data = JsonParser.parseString(raw.trim().replaceFirst("^for\\s*\\(\\s*;\\s*;\\s*\\)\\s*;", "")).getAsJsonObject();
            if (data.has("error") && data.get("error").isJsonPrimitive()) {
                String code = data.get("error").getAsString();
                return result(Status.UNKNOWN,"Route endpoint rejected the request (error " + code + "); this is not a missing-account response.");
            }
            JsonObject payloads = data.getAsJsonObject("payload").getAsJsonObject("payloads");
            JsonObject entry = payloads.getAsJsonObject("/" + handle);
            if (entry == null) return result(Status.UNKNOWN, "Requested profile missing from route response.");
            if (instagram) {
                JsonElement error = entry.get("error");
                if (error == null || !error.isJsonPrimitive() || !error.getAsJsonPrimitive().isBoolean()) return result(Status.UNKNOWN, "Route error flag missing or invalid.");
                return error.getAsBoolean() ? result(Status.UNAVAILABLE, "Instagram route error=true; profile unavailable.") : result(Status.EXISTS, "Instagram route error=false (private profiles also exist).");
            }
            JsonObject exports = entry.getAsJsonObject("result").getAsJsonObject("exports");
            String route = exports.get("canonicalRouteName").getAsString();
            if (route.equals("comet.fbweb.CometProfileRoute") || route.equals("comet.fbweb.CometPageRoute")) return result(Status.EXISTS, "Facebook route: " + route);
            if (route.equals("comet.fbweb.CometErrorRoute")) {
                JsonObject root = exports.getAsJsonObject("rootView");
                JsonObject props = root == null ? null : root.getAsJsonObject("props");
                if (props != null && (flag(props, "privacy") || flag(props, "isAdminViewingDeactivatedProfile")))
                    return result(Status.UNKNOWN, "Facebook error route indicates privacy restrictions or deactivation; not a missing-account confirmation.");
                return result(Status.UNAVAILABLE, "Facebook CometErrorRoute; unavailable to an anonymous visitor. Claimability is unverified.");
            }
            return result(Status.UNKNOWN, "Unrecognized Facebook route: " + route);
        } catch (RuntimeException e) { return result(Status.UNKNOWN, "Malformed or incomplete route response; no account conclusion."); }
    }
    private static boolean flag(JsonObject object, String key) {
        JsonElement e = object.get(key); return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isBoolean() && e.getAsBoolean();
    }
    static Result parseX(Reply page, String handle) {
        Result blocked = blocked(page); if (blocked != null) return blocked;
        String title = first(page.body, "(?is)<title[^>]*>([^<]*)</title>");
        String og = meta(page.body, "og:title");
        String lower = page.body.toLowerCase(Locale.ROOT);
        if (lower.contains("account suspended") || lower.contains("has been suspended")) return result(Status.SUSPENDED, "X reports suspension; the handle is not confirmed claimable.");
        if (page.code == 404 || page.code == 410 || title.matches("(?is).*\\b(?:not found|404)\\b.*") || og.matches("(?is).*\\b(?:not found|404)\\b.*"))
            return result(Status.UNAVAILABLE, "X returned a not-found response (HTTP " + page.code + ").");
        if ((og + " " + title).toLowerCase(Locale.ROOT).matches("(?s).*\\(@" + Pattern.quote(handle.toLowerCase(Locale.ROOT)) + "\\).*"))
            return result(Status.EXISTS, "X profile title identifies @" + handle + ".");
        return result(Status.UNKNOWN, meta(page.body, "robots").toLowerCase(Locale.ROOT).contains("noindex")
            ? "X noindex alone does not prove an account is missing." : "X returned no conclusive profile data; the page may require JavaScript or login.");
    }
    static String meta(String html, String key) {
        Matcher tags = Pattern.compile("(?is)<meta\\b[^>]*>").matcher(html);
        while (tags.find()) {
            String tag = tags.group();
            String name = first(tag, "(?i)(?:property|name)\\s*=\\s*[\"']([^\"']+)[\"']");
            if (name.equalsIgnoreCase(key)) return first(tag, "(?i)content\\s*=\\s*[\"']([^\"']*)[\"']");
        }
        return "";
    }
    static String first(String text, String... patterns) {
        for (String pattern : patterns) { Matcher m = Pattern.compile(pattern).matcher(text); if (m.find()) return m.group(1); }
        return "";
    }
}
