package burp;

import java.lang.reflect.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.io.File;

/** Offline regression tests against the real Burp interfaces and mocked callbacks. */
public final class BLHifyTest {
    private static int passed;
    private static void expect(boolean condition, String message) { if (!condition) throw new AssertionError(message); passed++; }
    private static void status(SocialChecker.Status expected, SocialChecker.Result actual, String message) { expect(actual.status == expected, message + ": " + actual.status + " / " + actual.reason); }
    private static String route(String handle,String entry) { return "for (;;);{\"payload\":{\"payloads\":{\"/" + handle + "\":" + entry + "}}}"; }
    private static String fb(String route,String props) { return "{\"result\":{\"exports\":{\"canonicalRouteName\":\"" + route + "\",\"rootView\":{\"props\":" + props + "}}}}"; }
    public static void main(String[] args) throws Exception {
        parserTests(); protocolTests(); transportTests(); integrationTests();
        System.out.println("PASS: " + passed + " assertions; offline native-check protocols and Burp/Swing integration.");
    }
    private static void transportTests() throws Exception {
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/get", exchange -> {
            java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
            try (java.util.zip.GZIPOutputStream gzip = new java.util.zip.GZIPOutputStream(bytes)) { gzip.write("compressed-profile".getBytes(StandardCharsets.UTF_8)); }
            exchange.getResponseHeaders().add("Set-Cookie","session=fixture; Path=/");
            exchange.getResponseHeaders().add("Content-Encoding","gzip");
            exchange.sendResponseHeaders(200,bytes.size()); exchange.getResponseBody().write(bytes.toByteArray()); exchange.close();
        });
        server.createContext("/post", exchange -> {
            String cookie = exchange.getRequestHeaders().getFirst("Cookie");
            String body = new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);
            byte[] answer = (exchange.getRequestMethod().equals("POST") && cookie != null && cookie.contains("session=fixture") && body.equals("route=test") ? "ok" : "bad").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,answer.length); exchange.getResponseBody().write(answer); exchange.close();
        });
        server.createContext("/redirect", exchange -> { exchange.getResponseHeaders().add("Location","https://evil.test/"); exchange.sendResponseHeaders(302,-1); exchange.close(); });
        server.start();
        try {
            String origin = "http://127.0.0.1:" + server.getAddress().getPort();
            SocialChecker.NativeTransport transport = new SocialChecker.NativeTransport();
            expect(transport.send(origin + "/get",null,Collections.emptyMap()).body.equals("compressed-profile"),"Native gzip decoding");
            expect(transport.send(origin + "/post","route=test",Collections.emptyMap()).body.equals("ok"),"Native POST and cookie continuity");
            boolean blocked = false;
            try { transport.send(origin + "/redirect",null,Collections.emptyMap()); } catch (java.io.IOException expected) { blocked = true; }
            expect(blocked,"Native cross-host redirect protection");
        } finally { server.stop(0); }
    }
    private static void parserTests() {
        expect(SocialChecker.socialHost("www.instagram.com"),"Do not harvest Instagram's own navigation");
        expect(!SocialChecker.socialHost("instagram.com.example.org"),"Social source host boundary");
        expect(!SocialChecker.profile("https://facebook.com/tr").supported,"Tracking endpoint excluded");
        String noisy = "<a href='https://instagram.com/?hl=en'>Language</a>"
            + "<a href='https://instagram.com/p/post'>Post</a>"
            + "<a href='https://facebook.com/tr'>Tracking</a>"
            + "<script>var html=\"<a href='https://x.com/fake'>fake</a>\";</script>"
            + "<!-- <a href='https://x.com/comment'>comment</a> -->"
            + "<link href='https://x.com/resource'>"
            + "<a href='https://www.instagram.com/xk9z_qlmfp_idealab_zz99'>Profile</a>";
        Map<String,SocialChecker.Profile> candidates = BLHifyBURP.candidates(noisy,true);
        expect(candidates.size() == 1,"Only real profile hyperlinks survive noise filtering");
        expect(candidates.values().iterator().next().handle.equals("xk9z_qlmfp_idealab_zz99"),"User's exact test handle discovered");
        expect(BLHifyBURP.candidates("<a href=https://x.com/example>Profile</a>",true).size() == 1,"Unquoted HTML href");
        SocialChecker.Result rejected = SocialChecker.parseRoute("for (;;);{\"error\":1357054,\"payload\":null}","a",true);
        status(SocialChecker.Status.UNKNOWN,rejected,"Instagram request failure is not a missing account");
        expect(rejected.reason.contains("1357054"),"Real route failure is preserved");
        status(SocialChecker.Status.EXISTS,SocialChecker.parseInstagramProfile(new SocialChecker.Reply(200,"https://www.instagram.com/api/v1/users/web_profile_info/","{\"status\":\"ok\",\"data\":{\"user\":{\"username\":\"Example\"}}}"),"example"),"Fallback verifies exact username");
        status(SocialChecker.Status.UNAVAILABLE,SocialChecker.parseInstagramProfile(new SocialChecker.Reply(200,"https://www.instagram.com/api/v1/users/web_profile_info/","{\"status\":\"ok\",\"data\":{\"user\":null}}"),"example"),"Successful null user is unavailable");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseInstagramProfile(new SocialChecker.Reply(429,"https://www.instagram.com/api/v1/users/web_profile_info/",""),"example"),"Fallback rate limit is not missing");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseInstagramProfile(new SocialChecker.Reply(200,"https://www.instagram.com/api/v1/users/web_profile_info/","{\"status\":\"ok\",\"data\":{\"user\":{\"username\":\"other\"}}}"),"example"),"Wrong fallback user is unknown");
        expect(SocialChecker.profile("https://twitter.com/OpenAI?ref=site").url.equals("https://x.com/openai"),"X alias normalization");
        expect(SocialChecker.profile("//www.instagram.com/Example/").supported,"Protocol-relative profile");
        expect(!SocialChecker.profile("https://instagram.com/p/ABC/").supported,"Posts are not profiles");
        expect(!SocialChecker.profile("https://x.com/intent/tweet").supported,"Share endpoint not profile");
        expect(!SocialChecker.profile("https://facebook.com/profile.php?id=123").supported,"Numeric profile retained without username misclassification");
        expect(!SocialChecker.profile("https://tiktok.com/@example").supported,"TikTok retained as unsupported");
        expect(SocialChecker.profile("https://x.com.evil.test/example") == null,"Host boundary");
        expect(SocialChecker.profile("https://x.com@evil.test/example") == null,"Userinfo rejected");
        expect(SocialChecker.profile("https://x.com:8000/example") == null,"Custom ports rejected");
        expect(!SocialChecker.profile("https://x.com/thishandleistoolong").supported,"Username length validation");
        expect(SocialChecker.profile("https://m.facebook.com/Example/").url.equals("https://www.facebook.com/example"),"Mobile Facebook normalization");
        expect(SocialChecker.LINKS.matcher(SocialChecker.decodedLinks("https:\\/\\/x.com\\/example")).find(),"Escaped JSON links");
        expect(!SocialChecker.LINKS.matcher("https://x.com.evil.test/example").find(),"Extraction host boundary");
        status(SocialChecker.Status.EXISTS,SocialChecker.parseRoute(route("a",fb("comet.fbweb.CometProfileRoute","{}")),"a",false),"Facebook profile");
        status(SocialChecker.Status.EXISTS,SocialChecker.parseRoute(route("a",fb("comet.fbweb.CometPageRoute","{}")),"a",false),"Facebook page");
        status(SocialChecker.Status.UNAVAILABLE,SocialChecker.parseRoute(route("a",fb("comet.fbweb.CometErrorRoute","{}")),"a",false),"Facebook error route");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseRoute(route("a",fb("comet.fbweb.CometErrorRoute","{\"privacy\":true}")),"a",false),"Facebook privacy");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseRoute(route("a",fb("comet.fbweb.CometErrorRoute","{\"isAdminViewingDeactivatedProfile\":true}")),"a",false),"Facebook deactivated");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseRoute("{}","a",false),"Missing payload");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseRoute("<html>login</html>","a",true),"HTML instead of JSON");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseRoute(route("other","{\"error\":true}"),"a",true),"Never inspect another username");
        status(SocialChecker.Status.UNAVAILABLE,SocialChecker.parseRoute(route("a","{\"error\":true}"),"a",true),"Instagram missing");
        status(SocialChecker.Status.EXISTS,SocialChecker.parseRoute(route("a","{\"error\":false}"),"a",true),"Instagram exists");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseRoute(route("a","{\"error\":\"false\"}"),"a",true),"Instagram requires actual boolean");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseX(new SocialChecker.Reply(200,"https://x.com/a","<title>X</title>"),"a"),"JS shell is unknown");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseX(new SocialChecker.Reply(200,"https://x.com/a","<meta content='noindex' name='robots'>"),"a"),"Noindex alone is unknown");
        status(SocialChecker.Status.EXISTS,SocialChecker.parseX(new SocialChecker.Reply(200,"https://x.com/a","<meta content='A (@a) / X' property='og:title'>"),"a"),"Reversed meta attributes");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseX(new SocialChecker.Reply(200,"https://x.com/a","<title>B (@abc) / X</title>"),"a"),"Exact handle match");
        status(SocialChecker.Status.UNAVAILABLE,SocialChecker.parseX(new SocialChecker.Reply(404,"https://x.com/a",""),"a"),"X 404");
        status(SocialChecker.Status.SUSPENDED,SocialChecker.parseX(new SocialChecker.Reply(200,"https://x.com/a","Account suspended"),"a"),"Suspended is separate");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseX(new SocialChecker.Reply(403,"https://x.com/a","Not Found"),"a"),"403 is not missing");
        status(SocialChecker.Status.UNKNOWN,SocialChecker.parseX(new SocialChecker.Reply(200,"https://x.com/i/flow/login","<title>404</title>"),"a"),"Login redirect wins");
        expect(BLHifyBURP.html("<a&\">").equals("&lt;a&amp;&quot;&gt;"),"Issue HTML escaped");
        expect(BLHifyBURP.csvCell("=1+1").equals("\"'=1+1\""),"CSV formula protection");
    }
    private static void protocolTests() {
        AtomicInteger fallbackCalls = new AtomicInteger();
        status(SocialChecker.Status.EXISTS,new SocialChecker().check(SocialChecker.profile("https://instagram.com/example"),(url,body,headers) -> {
            int call = fallbackCalls.incrementAndGet();
            if (call == 1) return new SocialChecker.Reply(200,url,"\"lsd\":\"token\" \"pageID\":\"httpErrorPage\"");
            if (call == 2) return new SocialChecker.Reply(200,url,"for (;;);{\"error\":1357054,\"payload\":null}");
            expect(url.endsWith("web_profile_info/?username=example"),"Fallback stays on Instagram's profile endpoint");
            expect(headers.containsKey("X-IG-App-ID"),"Fallback sends web app identifier");
            return new SocialChecker.Reply(200,url,"{\"status\":\"ok\",\"data\":{\"user\":{\"username\":\"example\"}}}");
        }),"Route rejection falls back to independent profile data");
        expect(fallbackCalls.get() == 3,"Fallback makes one additional request");
        SocialChecker.Result limited = new SocialChecker().check(SocialChecker.profile("https://instagram.com/example"),(url,body,headers) ->
            url.contains("web_profile_info") ? new SocialChecker.Reply(429,url,"")
            : body == null ? new SocialChecker.Reply(200,url,"\"lsd\":\"token\" \"pageID\":\"httpErrorPage\"")
            : new SocialChecker.Reply(200,url,"for (;;);{\"error\":1357054,\"payload\":null}"));
        expect(limited.status == SocialChecker.Status.UNKNOWN && limited.reason.contains("1357054") && limited.reason.contains("HTTP 429"),"Both live failure reasons remain visible");
        for (String platform : Arrays.asList("facebook","instagram")) {
            SocialChecker.Profile profile = SocialChecker.profile("https://www." + platform + ".com/example");
            AtomicInteger calls = new AtomicInteger();
            SocialChecker.Result result = new SocialChecker().check(profile,(url,body,headers) -> {
                if (calls.getAndIncrement() == 0) {
                    expect(body == null,"Initial GET");
                    return new SocialChecker.Reply(200,url,"\"LSD\",[],{\"token\":\"abc\"} \"__rev\":123 \"__hs\":\"fresh-package\"");
                }
                expect(url.endsWith("/ajax/bulk-route-definitions/"),"Native route endpoint");
                expect(body.contains("route_urls%5B0%5D=%2Fexample"),"Form encoded route");
                expect(body.contains("__rev=123") && body.contains("__hs=fresh-package"),"Fresh extracted params");
                expect(body.contains("jazoest=2294"),"Token-derived jazoest");
                expect(headers.get("X-FB-LSD").equals("abc"),"Fresh LSD header");
                expect(body.contains("__comet_req=" + (platform.equals("instagram") ? "7" : "15")),"Platform-specific comet version");
                return new SocialChecker.Reply(200,url,route("example",platform.equals("instagram") ? "{\"error\":false}" : fb("comet.fbweb.CometProfileRoute","{}")));
            });
            status(SocialChecker.Status.EXISTS,result,"Full native " + platform + " flow"); expect(calls.get() == 2,"Exactly GET then POST");
        }
        SocialChecker.Profile ig = SocialChecker.profile("https://instagram.com/example");
        status(SocialChecker.Status.EXISTS,new SocialChecker().check(ig,(u,b,h) -> new SocialChecker.Reply(200,u,"\"pageID\":\"ProfilePage\"")),"HTML fallback without LSD");
        status(SocialChecker.Status.UNKNOWN,new SocialChecker().check(ig,(u,b,h) -> new SocialChecker.Reply(429,u,"\"pageID\":\"httpErrorPage\"")),"Rate limit overrides HTML");
        status(SocialChecker.Status.UNKNOWN,new SocialChecker().check(ig,(u,b,h) -> new SocialChecker.Reply(200,u,"\"pageID\":\"httpErrorPage\"")),"Live regression: generic Instagram error also occurs for existing accounts");
        status(SocialChecker.Status.UNKNOWN,new SocialChecker().check(ig,(u,b,h) -> { throw new java.net.SocketTimeoutException("test"); }),"Timeout is unknown");
    }
    @SuppressWarnings("unchecked") private static <T> T mock(Class<T> type,InvocationHandler handler) { return (T) Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},handler); }
    private static Object field(Object object,String name) throws Exception { Field field = object.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(object); }
    private static void set(Object object,String name,Object value) throws Exception { Field field = object.getClass().getDeclaredField(name); field.setAccessible(true); field.set(object,value); }
    private static void integrationTests() throws Exception {
        AtomicInteger tabs = new AtomicInteger(), listeners = new AtomicInteger(), issues = new AtomicInteger();
        IExtensionHelpers helpers = mock(IExtensionHelpers.class,(p,m,a) -> {
            if (m.getName().equals("analyzeRequest")) return mock(IRequestInfo.class,(p2,m2,a2) -> {
                if (!m2.getName().equals("getUrl")) return null;
                String page = new String(((IHttpRequestResponse)a[0]).getRequest(),StandardCharsets.UTF_8);
                return new URL(page.startsWith("https://") ? page : "https://site.test/" + page);
            });
            if (m.getName().equals("analyzeResponse")) return mock(IResponseInfo.class,(p2,m2,a2) -> m2.getName().equals("getBodyOffset") ? 0 : m2.getName().equals("getHeaders") ? Arrays.asList("HTTP/1.1 200 OK","Content-Type: text/html") : null);
            return null;
        });
        IBurpExtenderCallbacks callbacks = mock(IBurpExtenderCallbacks.class,(p,m,a) -> {
            switch(m.getName()) {
                case "getHelpers": return helpers;
                case "addSuiteTab": tabs.incrementAndGet(); break;
                case "registerHttpListener": listeners.incrementAndGet(); break;
                case "isInScope": return true;
                case "addScanIssue": expect(((IScanIssue)a[0]).getIssueDetail().contains("https://site.test/"),"Issue source URL"); issues.incrementAndGet(); break;
            }
            return null;
        });
        BLHifyBURP extension = new BLHifyBURP(); extension.registerExtenderCallbacks(callbacks); set(extension,"automatic",false);
        expect(tabs.get() == 1 && listeners.get() == 1,"Burp tab and listener registered");
        IHttpService service = mock(IHttpService.class,(p,m,a) -> m.getName().equals("getHost") ? "site.test" : m.getName().equals("getPort") ? 443 : "https");
        for (String page : Arrays.asList("first","second","first","https://www.instagram.com/example/")) {
            IHttpRequestResponse message = mock(IHttpRequestResponse.class,(p,m,a) -> {
                switch(m.getName()) {
                    case "getRequest": return page.getBytes(StandardCharsets.UTF_8);
                    case "getResponse": return "<a href='https://twitter.com/Example'>x</a> <a href='https://x.com/example?ref=footer'>x</a>".getBytes(StandardCharsets.UTF_8);
                    case "getHttpService": return service;
                }
                return null;
            });
            extension.processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY,false,message);
        }
        ThreadPoolExecutor discovery = (ThreadPoolExecutor)field(extension,"discovery"); discovery.submit(() -> {}).get(5,TimeUnit.SECONDS);
        SwingUtilities.invokeAndWait(() -> {
            try {
                Map<?,?> inventory = (Map<?,?>)field(extension,"inventory"); expect(inventory.size() == 1,"Aliases deduplicated");
                Object entry = inventory.values().iterator().next(); expect(((Map<?,?>)field(entry,"sources")).size() == 2,"All source pages retained and deduplicated");
                set(entry,"result",SocialChecker.result(SocialChecker.Status.UNAVAILABLE,"Fixture: not found"));
                Method report = BLHifyBURP.class.getDeclaredMethod("report",entry.getClass()); report.setAccessible(true); report.invoke(extension,entry); report.invoke(extension,entry);
                expect(issues.get() == 2,"One issue per social/page pair");
                Method refresh = BLHifyBURP.class.getDeclaredMethod("refresh"); refresh.setAccessible(true); refresh.invoke(extension);
                ((JTable)field(extension,"table")).setRowSelectionInterval(0,0);
                JPanel panel = (JPanel)extension.getUiComponent(); panel.setSize(1450,820); layout(panel);
                BufferedImage screenshot = new BufferedImage(1450,820,BufferedImage.TYPE_INT_RGB); Graphics2D graphics = screenshot.createGraphics(); panel.printAll(graphics); graphics.dispose();
                ImageIO.write(screenshot,"png",new File("build/ui-preview.png"));
            } catch (Exception e) { throw new RuntimeException(e); }
        });
        extension.extensionUnloaded(); expect(discovery.isShutdown() && ((ExecutorService)field(extension,"checks")).isShutdown(),"Unload shuts down workers");
    }
    private static void layout(Container component) { component.doLayout(); for (Component child : component.getComponents()) if (child instanceof Container) layout((Container)child); }
}
