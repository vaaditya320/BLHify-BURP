package burp;
import java.util.*;
public final class InstagramProbe {
    public static void main(String[] args) throws Exception {
        for (String handle : args) {
            SocialChecker.NativeTransport t = new SocialChecker.NativeTransport();
            Map<String,String> headers = new HashMap<>();
            headers.put("X-IG-App-ID","936619743392459");
            headers.put("Accept","application/json");
            headers.put("Referer","https://www.instagram.com/" + handle + "/");
            SocialChecker.Reply r = t.send("https://www.instagram.com/api/v1/users/web_profile_info/?username=" + handle,null,headers);
            System.out.println(handle + ": HTTP " + r.code + " bytes=" + r.body.length());
            try {
                com.google.gson.JsonObject json = com.google.gson.JsonParser.parseString(r.body).getAsJsonObject();
                System.out.println("keys=" + json.keySet());
                for (String key : new String[]{"status","message"}) if (json.has(key)) System.out.println(key + "=" + json.get(key));
                if (json.has("data")) {
                    com.google.gson.JsonObject data = json.getAsJsonObject("data");
                    System.out.println("data keys=" + data.keySet());
                    if (data.has("user") && data.get("user").isJsonObject()) System.out.println("username=" + data.getAsJsonObject("user").get("username"));
                }
            } catch (RuntimeException e) { System.out.println("Not profile JSON"); }
        }
    }
}
