package burp;

/** Optional small live smoke test; not part of the repeatable offline suite. */
public final class LiveSmoke {
    public static void main(String[] args) {
        for (String url : args) {
            SocialChecker.Profile profile = SocialChecker.profile(url);
            if (profile == null) throw new IllegalArgumentException("Invalid social URL: " + url);
            SocialChecker.NativeTransport nativeTransport = new SocialChecker.NativeTransport();
            SocialChecker.Result result = new SocialChecker().check(profile, (target, body, headers) -> {
                SocialChecker.Reply reply = nativeTransport.send(target,body,headers);
                if (Boolean.getBoolean("blhify.debug")) {
                    System.out.println("  " + (body == null ? "GET" : "POST") + " HTTP " + reply.code + " bytes=" + reply.body.length());
                    if (body != null) {
                        System.out.println("  Route interpretation: " + SocialChecker.parseRoute(reply.body,profile.handle,profile.platform.equals("Instagram")).reason);
                        try {
                            com.google.gson.JsonObject json = com.google.gson.JsonParser.parseString(reply.body.replaceFirst("^for\\s*\\(;;\\);","")).getAsJsonObject();
                            System.out.println("  JSON keys: " + json.keySet());
                            for (String key : new String[]{"error","errorSummary","errorDescription"}) {
                                if (json.has(key)) System.out.println("  " + key + ": " + json.get(key));
                            }
                        } catch (RuntimeException ignored) { System.out.println("  Route response is not JSON."); }
                    }
                }
                return reply;
            });
            System.out.println(url + " => " + result.status + " | " + result.reason);
            if (Boolean.getBoolean("blhify.debug")) {
                try {
                    SocialChecker.Reply reply = new SocialChecker.NativeTransport().send(profile.url,null,java.util.Collections.emptyMap());
                    System.out.println("  GET: HTTP " + reply.code + " final=" + reply.url + " bytes=" + reply.body.length()
                        + " pageID=" + SocialChecker.first(reply.body,"\"pageID\"\\s*:\\s*\"([^\"]+)\"")
                        + " title=" + SocialChecker.first(reply.body,"(?is)<title[^>]*>([^<]*)</title>"));
                } catch (Exception e) { System.out.println("  GET diagnostic: " + e.getClass().getSimpleName()); }
            }
        }
    }
}
