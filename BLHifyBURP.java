package burp;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.zip.*;

/** UI and Burp integration. All inventory mutations take place on Swing's EDT. */
public class BLHifyBURP implements IBurpExtender, IHttpListener, ITab, IExtensionStateListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private volatile boolean unloaded, capture = true, automatic = true, scopeOnly;
    private final ThreadPoolExecutor checks = pool("BLHify-check", 2, 200);
    private final ThreadPoolExecutor discovery = pool("BLHify-discovery", 1, 24);
    private final AtomicInteger pendingUi = new AtomicInteger();
    private final Map<String,Long> cooldowns = new ConcurrentHashMap<>();
    private final Map<String,Entry> inventory = new LinkedHashMap<>();
    private final List<Entry> rows = new ArrayList<>();
    private JPanel panel;
    private JTable table;
    private final LinkModel model = new LinkModel();
    private TableRowSorter<LinkModel> sorter;
    private JTextArea details, activity;
    private JLabel summary;
    private JTextField search;
    private JComboBox<String> filter;
    private volatile int generation;
    private int sourceCount;
    private static final int MAX_LINKS = 10000, MAX_SOURCES = 500;

    private static ThreadPoolExecutor pool(String name, int size, int capacity) {
        AtomicInteger sequence = new AtomicInteger();
        return new ThreadPoolExecutor(size, size, 0, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(capacity), task -> {
            Thread thread = new Thread(task, name + "-" + sequence.incrementAndGet()); thread.setDaemon(true); return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
    }
    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks; this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("BLHify | Native Social Link Inspector");
        Runnable setup = () -> {
            buildUi(); callbacks.customizeUiComponent(panel); callbacks.addSuiteTab(this);
            callbacks.registerExtensionStateListener(this); callbacks.registerHttpListener(this);
            log("Ready. Capturing proxy responses; native anonymous checks enabled.");
        };
        try { if (SwingUtilities.isEventDispatchThread()) setup.run(); else SwingUtilities.invokeAndWait(setup); }
        catch (Exception e) { checks.shutdownNow(); discovery.shutdownNow(); throw new IllegalStateException("Unable to initialize BLHify", e); }
    }
    @Override public String getTabCaption() { return "BLHify"; }
    @Override public Component getUiComponent() { return panel; }
    private void buildUi() {
        panel = new JPanel(new BorderLayout(12,12)); panel.setBorder(BorderFactory.createEmptyBorder(18,18,18,18));
        JPanel header = new JPanel(new BorderLayout(8,8));
        JLabel title = new JLabel("BLHify  /  Social Link Inspector"); title.setFont(title.getFont().deriveFont(Font.BOLD, 24f));
        header.add(title, BorderLayout.NORTH);
        header.add(new JLabel("Native checks for Facebook, Instagram and X  •  Select a link to see every source page"), BorderLayout.CENTER);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        JCheckBox capturing = new JCheckBox("Capture proxy traffic", true); capturing.addActionListener(e -> capture = capturing.isSelected());
        JCheckBox auto = new JCheckBox("Auto-check new links", true); auto.addActionListener(e -> automatic = auto.isSelected());
        JCheckBox scoped = new JCheckBox("In-scope pages only", false); scoped.addActionListener(e -> scopeOnly = scoped.isSelected());
        controls.add(capturing); controls.add(auto); controls.add(scoped); header.add(controls, BorderLayout.SOUTH);
        panel.add(header, BorderLayout.NORTH);
        JPanel center = new JPanel(new BorderLayout(8,8));
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT,8,0));
        search = new JTextField(24); search.setToolTipText("Search social URL, source page, platform or reason");
        filter = new JComboBox<>(new String[]{"All statuses", "UNAVAILABLE", "EXISTS", "UNKNOWN", "SUSPENDED", "UNSUPPORTED", "DISCOVERED", "QUEUED", "CHECKING"});
        toolbar.add(new JLabel("Find")); toolbar.add(search); toolbar.add(filter);
        button(toolbar, "Check selected", () -> selected().forEach(this::queue));
        button(toolbar, "Check pending / unknown", () -> new ArrayList<>(rows).stream().filter(e -> e.result.status == SocialChecker.Status.DISCOVERED || e.result.status == SocialChecker.Status.UNKNOWN).forEach(this::queue));
        button(toolbar, "Export CSV", this::exportCsv);
        button(toolbar, "Clear", () -> { generation++; checks.getQueue().clear(); inventory.clear(); rows.clear(); sourceCount = 0; model.fireTableDataChanged(); refresh(); log("Inventory cleared. Already reported Burp issues remain in Burp."); });
        JPanel toolbarRows = new JPanel(new GridLayout(0,1,0,7));
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT,8,0));
        while (toolbar.getComponentCount() > 3) actionRow.add(toolbar.getComponent(3));
        toolbarRows.add(toolbar); toolbarRows.add(actionRow); center.add(toolbarRows, BorderLayout.NORTH);
        table = new JTable(model); table.setRowHeight(28); table.setAutoCreateRowSorter(false); table.setFillsViewportHeight(true);
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        sorter = new TableRowSorter<>(model); table.setRowSorter(sorter);
        table.getColumnModel().getColumn(1).setPreferredWidth(330); table.getColumnModel().getColumn(4).setPreferredWidth(320);
        table.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t,Object v,boolean selected,boolean focus,int row,int col) {
                super.getTableCellRendererComponent(t,v,selected,focus,row,col);
                setFont(getFont().deriveFont(Font.BOLD));
                if (!selected) {
                    String status = String.valueOf(v);
                    setForeground(status.equals("UNAVAILABLE") ? new Color(195,65,65) : status.equals("EXISTS") ? new Color(35,145,100)
                        : status.equals("UNKNOWN") || status.equals("SUSPENDED") ? new Color(180,125,35) : t.getForeground());
                }
                return this;
            }
        });
        details = area(); details.setText("Browse through Burp Proxy to discover social links.\nChecks run anonymously against the platforms themselves.\nUnavailable does not establish that a handle can be registered.");
        activity = area();
        JPanel detailPanel = new JPanel(new BorderLayout(5,5));
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        button(actions, "Copy social URL", () -> { List<Entry> selection = selected(); if (!selection.isEmpty()) copy(selection.get(0).profile.url); });
        button(actions, "Copy source URLs", () -> { List<Entry> selection = selected(); if (!selection.isEmpty()) copy(String.join("\n", selection.get(0).sources.keySet())); });
        detailPanel.add(actions, BorderLayout.NORTH); detailPanel.add(new JScrollPane(details), BorderLayout.CENTER);
        JTabbedPane bottom = new JTabbedPane(); bottom.addTab("Link details & source pages", detailPanel); bottom.addTab("Activity", new JScrollPane(activity));
        JScrollPane tableScroll = new JScrollPane(table); tableScroll.setColumnHeaderView(table.getTableHeader());
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottom); split.setResizeWeight(.65); split.setDividerLocation(340);
        center.add(split, BorderLayout.CENTER); panel.add(center, BorderLayout.CENTER);
        summary = new JLabel("No social links yet"); panel.add(summary, BorderLayout.SOUTH);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showDetails(); });
        search.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { applyFilter(); } public void removeUpdate(DocumentEvent e) { applyFilter(); } public void changedUpdate(DocumentEvent e) { applyFilter(); }
        });
        filter.addActionListener(e -> applyFilter());
    }
    private static JTextArea area() { JTextArea area = new JTextArea(); area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); area.setBorder(BorderFactory.createEmptyBorder(10,10,10,10)); return area; }
    private static void button(JPanel target,String title,Runnable action) { JButton button = new JButton(title); button.addActionListener(e -> action.run()); target.add(button); }
    private void copy(String value) { try { Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null); } catch (RuntimeException e) { log("Clipboard unavailable: " + e.getMessage()); } }
    private void applyFilter() {
        final String query = search.getText().toLowerCase(Locale.ROOT); final String status = (String) filter.getSelectedItem();
        sorter.setRowFilter(new RowFilter<LinkModel,Integer>() {
            @Override public boolean include(RowFilter.Entry<? extends LinkModel,? extends Integer> item) {
                BLHifyBURP.Entry entry = rows.get(item.getIdentifier());
                return ("All statuses".equals(status) || entry.result.status.name().equals(status))
                    && (entry.profile.url + " " + entry.profile.platform + " " + entry.result.reason + " " + String.join(" ",entry.sources.keySet())).toLowerCase(Locale.ROOT).contains(query);
            }
        });
    }
    private List<Entry> selected() {
        List<Entry> result = new ArrayList<>();
        for (int index : table.getSelectedRows()) result.add(rows.get(table.convertRowIndexToModel(index)));
        return result;
    }
    private void showDetails() {
        List<Entry> selection = selected(); if (selection.isEmpty()) { details.setText("Select a social link to inspect its result and source pages."); return; }
        Entry entry = selection.get(0);
        StringBuilder text = new StringBuilder(entry.profile.url).append("\n\nStatus: ").append(entry.result.status)
            .append("\nEvidence: ").append(entry.result.reason).append("\nLast checked: ").append(entry.checked)
            .append("\n\nFound on ").append(entry.sources.size()).append(" page(s):\n");
        for (Source source : entry.sources.values()) text.append("\n").append(source.url).append("\n  Original link: ").append(source.original).append('\n');
        details.setText(text.toString()); details.setCaretPosition(0);
    }
    private void refresh() {
        long unavailable = rows.stream().filter(e -> e.result.status == SocialChecker.Status.UNAVAILABLE).count();
        long unknown = rows.stream().filter(e -> e.result.status == SocialChecker.Status.UNKNOWN).count();
        int sources = rows.stream().mapToInt(e -> e.sources.size()).sum();
        summary.setText(rows.size() + " links   •   " + sources + " source associations   •   " + unavailable + " unavailable   •   " + unknown + " unknown   |   Unavailable ≠ claimable");
        applyFilter(); showDetails();
    }
    private void changed() {
        List<Entry> selection = selected();
        model.fireTableDataChanged();
        for (Entry entry : selection) {
            int index = rows.indexOf(entry);
            if (index >= 0) { int view = table.convertRowIndexToView(index); if (view >= 0) table.addRowSelectionInterval(view,view); }
        }
        refresh();
    }
    private void log(String text) {
        if (!SwingUtilities.isEventDispatchThread()) { SwingUtilities.invokeLater(() -> log(text)); return; }
        if (unloaded) return;
        callbacks.printOutput("[BLHify] " + text);
        activity.append(LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "  " + text + "\n");
        if (activity.getDocument().getLength() > 60000) activity.replaceRange("", 0, 15000);
        activity.setCaretPosition(activity.getDocument().getLength());
    }
    @Override public void processHttpMessage(int toolFlag, boolean request, IHttpRequestResponse message) {
        if (request || toolFlag != IBurpExtenderCallbacks.TOOL_PROXY || unloaded || !capture || message.getResponse() == null) return;
        try {
            URL url = helpers.analyzeRequest(message).getUrl();
            if (SocialChecker.socialHost(url.getHost())) return;
            if (scopeOnly && !callbacks.isInScope(url)) return;
            byte[] response = message.getResponse();
            if (response.length > 8 * 1024 * 1024) return;
            // Snapshot before the listener returns; Burp may subsequently mutate the message.
            byte[] snapshot = response.clone();
            IHttpService service = message.getHttpService();
            int epoch = generation;
            discovery.execute(() -> discover(url, service, snapshot, epoch));
        } catch (RejectedExecutionException e) { callbacks.printError("BLHify discovery queue full; response skipped."); }
        catch (RuntimeException e) { callbacks.printError("BLHify discovery error: " + e.getMessage()); }
    }
    private void discover(URL page, IHttpService service, byte[] response, int epoch) {
        if (unloaded) return;
        try {
            IResponseInfo info = helpers.analyzeResponse(response);
            String type = "", encoding = "";
            for (String header : info.getHeaders()) {
                if (header.toLowerCase(Locale.ROOT).startsWith("content-type:")) type = header.toLowerCase(Locale.ROOT);
                if (header.toLowerCase(Locale.ROOT).startsWith("content-encoding:")) encoding = header.substring(header.indexOf(':') + 1).trim();
            }
            if (!type.isEmpty() && !(type.contains("text/") || type.contains("json") || type.contains("javascript") || type.contains("xml"))) return;
            InputStream input = new ByteArrayInputStream(response, info.getBodyOffset(), response.length - info.getBodyOffset());
            if (encoding.equalsIgnoreCase("gzip")) input = new GZIPInputStream(input);
            else if (encoding.equalsIgnoreCase("deflate")) input = new InflaterInputStream(input);
            else if (!encoding.isEmpty() && !encoding.equalsIgnoreCase("identity")) return;
            byte[] body;
            try (InputStream in = input) { body = in.readNBytes(4 * 1024 * 1024 + 1); }
            if (body.length > 4 * 1024 * 1024) { log("Skipped oversized response body: " + page); return; }
            Map<String,SocialChecker.Profile> found = candidates(new String(body, StandardCharsets.UTF_8),type.contains("html") || type.isEmpty());
            if (found.isEmpty()) return;
            if (pendingUi.incrementAndGet() > 100) { pendingUi.decrementAndGet(); callbacks.printError("BLHify UI queue full; response skipped."); return; }
            SwingUtilities.invokeLater(() -> {
                try {
                    if (unloaded || epoch != generation) return;
                    for (Map.Entry<String,SocialChecker.Profile> foundLink : found.entrySet()) record(foundLink.getValue(),new Source(page,service,foundLink.getKey()));
                    changed();
                } finally { pendingUi.decrementAndGet(); }
            });
        } catch (Exception e) { log("Could not inspect response from " + page + ": " + e.getMessage()); }
    }
    static Map<String,SocialChecker.Profile> candidates(String body, boolean html) {
        String text = SocialChecker.decodedLinks(body);
        if (html) {
            text = text.replaceAll("(?is)<!--.*?-->|<(script|style)\\b[^>]*>.*?</\\1\\s*>","");
            Matcher anchors = java.util.regex.Pattern.compile("(?is)<a\\b[^>]*\\bhref\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))").matcher(text);
            StringBuilder links = new StringBuilder();
            while (anchors.find()) {
                String href = anchors.group(1) != null ? anchors.group(1) : anchors.group(2) != null ? anchors.group(2) : anchors.group(3);
                links.append(href).append('\n');
            }
            text = links.toString();
        }
        Matcher matcher = SocialChecker.LINKS.matcher(text);
        Map<String,SocialChecker.Profile> found = new LinkedHashMap<>();
        while (matcher.find() && found.size() < 500) {
            String raw = matcher.group(); SocialChecker.Profile profile = SocialChecker.profile(raw);
            if (profile != null && profile.supported) found.put(raw,profile);
        }
        return found;
    }
    private void record(SocialChecker.Profile profile, Source source) {
        if (!profile.supported) return;
        Entry entry = inventory.get(profile.url);
        if (sourceCount >= 50000 && (entry == null || !entry.sources.containsKey(source.url.toString()))) {
            log("Source association limit reached (50,000). Export and clear to continue."); return;
        }
        if (entry == null) {
            if (rows.size() >= MAX_LINKS) { log("Inventory limit reached (10,000 links). Export and clear to continue."); return; }
            entry = new Entry(profile); inventory.put(profile.url,entry); rows.add(entry);
            model.fireTableRowsInserted(rows.size()-1, rows.size()-1);
        }
        if (entry.sources.size() < MAX_SOURCES || entry.sources.containsKey(source.url.toString())) {
            if (entry.sources.putIfAbsent(source.url.toString(),source) == null) sourceCount++;
        }
        else { log("Source limit reached for " + profile.url); return; }
        if (automatic && entry.result.status == SocialChecker.Status.DISCOVERED) queue(entry);
        report(entry);
    }
    private void queue(Entry entry) {
        if (unloaded || !entry.profile.supported || entry.busy) return;
        int epoch = generation;
        entry.busy = true; entry.result = SocialChecker.result(SocialChecker.Status.QUEUED,"Waiting for a native check.");
        try {
            checks.execute(() -> {
                SwingUtilities.invokeLater(() -> { if (valid(entry,epoch)) { entry.result = SocialChecker.result(SocialChecker.Status.CHECKING,"Contacting " + entry.profile.platform + " anonymously..."); changed(); } });
                SocialChecker.Result result;
                if (System.currentTimeMillis() < cooldowns.getOrDefault(entry.profile.platform,0L)) {
                    result = SocialChecker.result(SocialChecker.Status.UNKNOWN,"Platform cooling down after HTTP 429; retry in a few minutes.");
                } else {
                    result = new SocialChecker().check(entry.profile);
                    if (result.reason.contains("HTTP 429")) cooldowns.put(entry.profile.platform,System.currentTimeMillis() + 120000L);
                }
                final SocialChecker.Result completed = result;
                SwingUtilities.invokeLater(() -> {
                    if (!valid(entry,epoch)) return;
                    entry.busy = false; entry.result = completed; entry.checked = java.time.Instant.now().toString();
                    log(entry.profile.platform + " " + entry.profile.url + " -> " + completed.status + ": " + completed.reason);
                    report(entry); changed();
                });
                try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            });
        } catch (RejectedExecutionException e) { entry.busy = false; entry.result = SocialChecker.result(SocialChecker.Status.DISCOVERED,"Check queue full; use Check pending / unknown to retry."); }
        changed();
    }
    private boolean valid(Entry entry,int epoch) { return !unloaded && epoch == generation && inventory.get(entry.profile.url) == entry; }
    private void report(Entry entry) {
        if (entry.result.status != SocialChecker.Status.UNAVAILABLE) return;
        for (Source source : entry.sources.values()) {
            if (entry.reported.contains(source.url.toString())) continue;
            try { callbacks.addScanIssue(new BLHIssue(source,entry.profile.url,entry.result.reason)); entry.reported.add(source.url.toString()); }
            catch (RuntimeException e) { log("Unable to add Burp issue: " + e.getMessage()); }
        }
    }
    private void exportCsv() {
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new File("BLHify-links.csv"));
        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        File target = chooser.getSelectedFile();
        if (target.exists() && JOptionPane.showConfirmDialog(panel,"Replace " + target.getName() + "?","Export CSV",JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        StringBuilder csv = new StringBuilder("Platform,Social URL,Status,Reason,Source page,Original URL,Checked at UTC\r\n");
        for (Entry entry : rows) for (Source source : entry.sources.values()) {
            StringJoiner line = new StringJoiner(",");
            for (String value : Arrays.asList(entry.profile.platform,entry.profile.url,entry.result.status.name(),entry.result.reason,source.url.toString(),source.original,entry.checked)) line.add(csvCell(value));
            csv.append(line).append("\r\n");
        }
        new SwingWorker<Void,Void>() {
            @Override protected Void doInBackground() throws Exception { Files.write(target.toPath(),csv.toString().getBytes(StandardCharsets.UTF_8)); return null; }
            @Override protected void done() { try { get(); log("Exported inventory to " + target); } catch (Exception e) { log("CSV export failed: " + e.getMessage()); } }
        }.execute();
    }
    static String csvCell(String value) { if (value.matches("^[=+@\\-\\t\\r\\n].*")) value = "'" + value; return "\"" + value.replace("\"","\"\"") + "\""; }
    @Override public void extensionUnloaded() { unloaded = true; checks.shutdownNow(); discovery.shutdownNow(); }
    private static class Source {
        final URL url; final IHttpService service; final String original;
        Source(URL url,IHttpService service,String original) { this.url = url; this.service = service; this.original = original; }
    }
    private static class Entry {
        final SocialChecker.Profile profile;
        final Map<String,Source> sources = new LinkedHashMap<>();
        final Set<String> reported = new HashSet<>();
        SocialChecker.Result result; boolean busy; String checked = "Not checked";
        Entry(SocialChecker.Profile profile) { this.profile = profile; result = SocialChecker.result(profile.supported ? SocialChecker.Status.DISCOVERED : SocialChecker.Status.UNSUPPORTED,profile.supported ? "Waiting to be checked." : "Recorded only: unsupported platform or non-profile URL."); }
    }
    private final class LinkModel extends AbstractTableModel {
        private final String[] columns = {"Platform","Social link","Status","Pages","Evidence / reason","Checked (UTC)"};
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int c) { return columns[c]; } public Class<?> getColumnClass(int c) { return c == 3 ? Integer.class : String.class; }
        public Object getValueAt(int r,int c) {
            Entry entry = rows.get(r);
            switch(c) { case 0: return entry.profile.platform; case 1: return entry.profile.url; case 2: return entry.result.status.name(); case 3: return entry.sources.size(); case 4: return entry.result.reason; default: return entry.checked; }
        }
    }
    static String html(String value) { return value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&#39;"); }
    private static final class BLHIssue implements IScanIssue {
        private final Source source; private final String social, reason;
        BLHIssue(Source source,String social,String reason) { this.source = source; this.social = social; this.reason = reason; }
        public URL getUrl() { return source.url; } public String getIssueName() { return "Unavailable social profile link"; }
        public int getIssueType() { return 0x08000000; } public String getSeverity() { return "Information"; } public String getConfidence() { return "Tentative"; }
        public String getIssueBackground() { return "An unavailable social profile may leave a stale link. Account availability and handle claimability require manual verification."; }
        public String getRemediationBackground() { return "Verify the intended account and update or remove stale links."; }
        public String getIssueDetail() { return "Social profile: <b>" + html(social) + "</b><br>Found on: " + html(source.url.toString()) + "<br>Signal: " + html(reason) + "<br>This anonymous check does not prove account deletion or a takeover vulnerability."; }
        public String getRemediationDetail() { return null; } public IHttpRequestResponse[] getHttpMessages() { return null; }
        public IHttpService getHttpService() { return source.service; }
    }
}
