package com.example.burpchain;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import javax.swing.JButton;
import javax.swing.AbstractAction;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.ButtonGroup;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.BorderFactory;
import javax.swing.JDialog;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.JPopupMenu;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JFileChooser;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;

public final class ChainExtension implements BurpExtension {
    private static final String WIKI_URL = "https://github.com/Goultarde/requests_chainer/wiki";
    private MontoyaApi api;
    private Component suiteTab;
    private volatile boolean intruderChainEnabled;
    private volatile String intruderTargetUrl;
    private volatile int intruderTargetIndex;
    private final ThreadLocal<Boolean> intruderChainRunning = ThreadLocal.withInitial(() -> false);
    private final List<ChainStep> steps = new ArrayList<>();
    private final Map<String, List<ChainStep>> namedChains = new LinkedHashMap<>();
    private String currentChainName = "Default";
    private boolean switchingChain;
    private final StepTable model = new StepTable();
    private final JTable table = new JTable(model);
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final JTextPane log = new JTextPane();
    private final JLabel status = new JLabel("Select requests in Proxy history, then right-click > Add to Requests Chainer.");
    private volatile boolean running;
    private boolean findingChain;
    private ChainStep displayedStep;
    private final JComboBox<String> variableBox = new JComboBox<>();
    private final JComboBox<String> chainSelector = new JComboBox<>();
    private final JTextField variableSearch = new JTextField(12);
    private final JSpinner repetitionCount = new JSpinner(new SpinnerNumberModel(1, 1, 1000, 1));
    private final Deque<byte[]> requestUndo = new ArrayDeque<>();
    private java.io.File lastChainDirectory;
    private java.io.File lastLogDirectory;
    private final TabActivityIndicator tabActivity = new TabActivityIndicator();
    private javax.swing.Timer trafficTimer;
    private boolean tabIndicatorFailureLogged;

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Requests Chainer");
        suiteTab = buildPanel();
        api.userInterface().registerSuiteTab("Requests Chainer", suiteTab);
        api.userInterface().registerContextMenuItemsProvider(new Menu());
        api.http().registerSessionHandlingAction(new ChainSessionAction());
    }

    private Component buildPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        root.setPreferredSize(new java.awt.Dimension(1200, 800));
        JButton up = new JButton("Move up");
        JButton down = new JButton("Move down");
        up.setToolTipText("Move the selected request up (Shift+Up in the request list)");
        down.setToolTipText("Move the selected request down (Shift+Down in the request list)");
        JButton disable = new JButton("Disable selected");
        JButton enable = new JButton("Enable selected");
        JButton remove = new JButton("Remove");
        JButton save = new JButton("Save request edit");
        JButton variable = new JButton("Variable from response selection");
        JButton insert = new JButton("Insert variable");
        JButton intruder = new JButton("Send target to Intruder");
        JButton repeater = new JButton("Send to Repeater");
        JButton pointRequest = new JButton("Point this request");
        JButton sessionRule = new JButton("⚙ Configure session rule");
        JButton saveChain = new JButton("Save chains");
        JButton loadChain = new JButton("Load chains");
        JButton help = new JButton("Help");
        JButton automate = new JButton("Automate chain finding");
        automate.setToolTipText("Build a new chain from preceding responses in same-origin Proxy history");
        automate.addActionListener(e -> automateChainFinding());
        JButton findSelection = new JButton("Find source for selection");
        findSelection.setToolTipText("Find a prior response containing the selected request value, then choose one source to insert");
        findSelection.addActionListener(e -> findSourceForSelection());
        JButton deleteVariable = new JButton("Delete variable");
        JButton editVariable = new JButton("Edit variable");
        JButton replaceAll = new JButton("Replace in all requests");
        JButton propagateHeader = new JButton("Use variable in all headers");
        JButton newChain = new JButton("New chain");
        JButton run = new JButton("Run chain");
        JButton clear = new JButton("Clear chain");
        chainSelector.addItem(currentChainName);
        stylePrimaryButton(run, new Color(0xD96A1D));
        stylePrimaryButton(variable, new Color(0x286EAC));
        stylePrimaryButton(automate, new Color(0x287A48));
        run.setToolTipText("Execute all requests in order (Ctrl+Alt+R)");
        intruder.setToolTipText("Use the selected request as the Intruder target (Ctrl+I)");
        repeater.setToolTipText("Open the selected request(s) in Burp Repeater (Ctrl+R)");
        pointRequest.setToolTipText("Use the selected request as the session-rule target without sending it again");
        variable.setToolTipText("Select a value in the response editor to create a reusable variable");
        variableSearch.setToolTipText("Filter the variable list");
        variableBox.setToolTipText("Select a variable to insert or manage");
        chainSelector.setToolTipText("Choose the chain to edit");
        help.setToolTipText("Open the Requests Chainer wiki in your browser");
        chainSelector.setPrototypeDisplayValue("A chain with a long name");
        variableBox.setPrototypeDisplayValue("A long variable name");
        repetitionCount.setToolTipText("Number of complete chain executions (1-1000)");

        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));
        Color separator = javax.swing.UIManager.getColor("Separator.foreground");
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0,
                separator != null ? separator : Color.GRAY));
        top.add(toolbarRow("CHAIN", new JLabel("Name:"), chainSelector, newChain, saveChain, loadChain, automate, findSelection, help));
        top.add(toolbarRow("RUN", run, new JLabel("Runs:"), repetitionCount, clear, intruder, repeater, pointRequest, sessionRule));
        top.add(toolbarRow("VARIABLES", new JLabel("Find:"), variableSearch, variableBox, insert, variable, editVariable, deleteVariable));
        top.add(toolbarRow("EDIT", save, replaceAll, propagateHeader));
        root.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                top.revalidate();
                root.revalidate();
            }
        });
        root.add(top, BorderLayout.NORTH);
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();
        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        log.setMargin(new java.awt.Insets(7, 9, 7, 9));
        table.setRowHeight(Math.max(26, table.getRowHeight()));
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setFillsViewportHeight(true);
        table.setShowVerticalLines(true);
        table.setShowHorizontalLines(true);
        table.setIntercellSpacing(new java.awt.Dimension(1, 1));
        updateStepTableGridColor();
        table.addPropertyChangeListener("UI", event -> updateStepTableGridColor());
        javax.swing.table.TableCellRenderer headerRenderer = table.getTableHeader().getDefaultRenderer();
        Component headerSample = headerRenderer.getTableCellRendererComponent(table, "", false, false, -1, 0);
        javax.swing.border.Border headerBorder = headerSample instanceof JComponent component
                ? component.getBorder() : null;
        table.getTableHeader().setDefaultRenderer((owner, value, selected, focused, row, column) -> {
            Component header = headerRenderer.getTableCellRendererComponent(owner, value, selected, focused, row, column);
            if (header instanceof JComponent component) {
                component.setBorder(BorderFactory.createCompoundBorder(headerBorder,
                        BorderFactory.createMatteBorder(0, 0, 0, 1, table.getGridColor())));
            }
            return header;
        });
        table.getColumnModel().getColumn(0).setPreferredWidth(68);
        table.getColumnModel().getColumn(0).setMaxWidth(85);
        table.getColumnModel().getColumn(1).setPreferredWidth(55);
        table.getColumnModel().getColumn(1).setMaxWidth(80);
        table.getColumnModel().getColumn(2).setPreferredWidth(600);
        table.getColumnModel().getColumn(3).setPreferredWidth(250);
        JPanel stepsPanel = new JPanel(new BorderLayout(4, 4));
        JPanel stepsHeader = new JPanel(new WrapLayout(FlowLayout.LEFT, 5, 0));
        stepsHeader.add(sectionTitle("Chain steps"));
        stepsHeader.add(up);
        stepsHeader.add(down);
        stepsHeader.add(disable);
        stepsHeader.add(enable);
        stepsHeader.add(remove);
        stepsHeader.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) { stepsPanel.revalidate(); }
        });
        stepsPanel.add(stepsHeader, BorderLayout.NORTH);
        stepsPanel.add(new JScrollPane(table), BorderLayout.CENTER);
        // Montoya's native editors provide their own scrolling and syntax coloring.
        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                editorPanel("Request · editable", requestEditor.uiComponent()),
                editorPanel("Response · select a value to create a variable", responseEditor.uiComponent()));
        editors.setResizeWeight(0.5);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, stepsPanel, editors);
        main.setResizeWeight(0.3);
        JPanel bottom = new JPanel(new BorderLayout());
        JPanel logHeader = new JPanel(new BorderLayout(6, 2));
        logHeader.add(sectionTitle("Activity log"), BorderLayout.WEST);
        status.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        JButton copyLog = new JButton("Copy");
        copyLog.setToolTipText("Copy the activity log to the clipboard");
        copyLog.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection(log.getText()), null);
            status.setText("Activity log copied.");
        });
        JButton saveLog = new JButton("Save log");
        saveLog.setToolTipText("Save the activity log shown below as a UTF-8 .log file");
        saveLog.addActionListener(e -> saveActivityLog());
        JButton clearLog = new JButton("Clear log");
        clearLog.addActionListener(e -> log.setText(""));
        JPanel logActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        logActions.add(copyLog);
        logActions.add(saveLog);
        logActions.add(clearLog);
        logHeader.add(logActions, BorderLayout.EAST);
        JPanel logTop = new JPanel(new BorderLayout());
        logTop.add(logHeader, BorderLayout.NORTH);
        logTop.add(status, BorderLayout.SOUTH);
        bottom.add(logTop, BorderLayout.NORTH);
        bottom.add(new JScrollPane(log), BorderLayout.CENTER);
        JSplitPane content = new JSplitPane(JSplitPane.VERTICAL_SPLIT, main, bottom);
        content.setResizeWeight(0.8);
        content.setOneTouchExpandable(true);
        content.setDividerSize(7);
        main.setDividerSize(7);
        editors.setDividerSize(7);
        root.add(content, BorderLayout.CENTER);
        root.setFocusable(true);
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control alt R"), "requests-chainer-run");
        root.getActionMap().put("requests-chainer-run", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { runChain(); }
        });
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control R"), "requests-chainer-repeater");
        root.getActionMap().put("requests-chainer-repeater", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { sendSelectedToRepeater(); }
        });
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control I"), "requests-chainer-intruder");
        root.getActionMap().put("requests-chainer-intruder", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { sendTargetToIntruder(); }
        });
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control Z"), "requests-chainer-undo");
        root.getActionMap().put("requests-chainer-undo", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { undoRequestEdit(); }
        });
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelected(); });
        table.setRowSelectionAllowed(true);
        table.setColumnSelectionAllowed(false);
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("shift UP"), "requests-chainer-move-up");
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("shift DOWN"), "requests-chainer-move-down");
        table.getActionMap().put("requests-chainer-move-up", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { move(-1); }
        });
        table.getActionMap().put("requests-chainer-move-down", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { move(1); }
        });
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { showTablePopup(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { showTablePopup(e); }
        });
        up.addActionListener(e -> move(-1));
        down.addActionListener(e -> move(1));
        disable.addActionListener(e -> setSelectedStepsEnabled(false));
        enable.addActionListener(e -> setSelectedStepsEnabled(true));
        remove.addActionListener(e -> removeSelected());
        save.addActionListener(e -> { saveSelected(); status.setText("Request edit saved for the selected chain step."); });
        variable.addActionListener(e -> createVariable(selectedStep(), selectedText(responseEditor), selectedOffset(responseEditor)));
        insert.addActionListener(e -> insertVariable());
        intruder.addActionListener(e -> sendTargetToIntruder());
        repeater.addActionListener(e -> sendSelectedToRepeater());
        pointRequest.addActionListener(e -> pointSelectedRequest());
        sessionRule.addActionListener(e -> showSessionRuleInstructions());
        saveChain.addActionListener(e -> saveChain());
        loadChain.addActionListener(e -> loadChain());
        help.addActionListener(e -> openWiki());
        deleteVariable.addActionListener(e -> deleteVariable());
        editVariable.addActionListener(e -> editVariable());
        newChain.addActionListener(e -> createNewChain());
        chainSelector.addActionListener(e -> switchChain((String) chainSelector.getSelectedItem()));
        replaceAll.addActionListener(e -> replaceAcrossRequests());
        propagateHeader.addActionListener(e -> propagateVariableHeader());
        run.addActionListener(e -> runChain());
        clear.addActionListener(e -> {
            steps.clear(); model.fireTableDataChanged(); showSelected();
            status.setText("Chain cleared. Add requests from Proxy history.");
            appendLog(LogLevel.INFO, "CHAIN", "Chain cleared");
        });
        variableSearch.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshVariables(); }
            public void removeUpdate(DocumentEvent e) { refreshVariables(); }
            public void changedUpdate(DocumentEvent e) { refreshVariables(); }
        });
        return root;
    }

    private JPanel toolbarRow(String title, Component... controls) {
        JPanel row = new JPanel(new WrapLayout(FlowLayout.LEFT, 6, 3));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 11f));
        Color muted = javax.swing.UIManager.getColor("Label.disabledForeground");
        label.setForeground(muted != null ? muted : Color.GRAY);
        label.setPreferredSize(new java.awt.Dimension(76, label.getPreferredSize().height));
        row.add(label);
        for (Component control : controls) row.add(control);
        return row;
    }

    private JLabel sectionTitle(String title) {
        JLabel label = new JLabel(title);
        label.setFont(label.getFont().deriveFont(Font.BOLD));
        label.setBorder(BorderFactory.createEmptyBorder(3, 5, 3, 5));
        return label;
    }

    private void updateStepTableGridColor() {
        Color background = table.getBackground();
        Color foreground = table.getForeground();
        if (background == null || foreground == null) return;
        // Derive the divider from Burp's current theme, with enough contrast on both light and dark tables.
        double foregroundWeight = 0.35;
        int red = (int) Math.round(background.getRed() * (1 - foregroundWeight) + foreground.getRed() * foregroundWeight);
        int green = (int) Math.round(background.getGreen() * (1 - foregroundWeight) + foreground.getGreen() * foregroundWeight);
        int blue = (int) Math.round(background.getBlue() * (1 - foregroundWeight) + foreground.getBlue() * foregroundWeight);
        table.setGridColor(new Color(red, green, blue));
        table.repaint();
        if (table.getTableHeader() != null) table.getTableHeader().repaint();
    }

    private JPanel editorPanel(String title, Component editor) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(sectionTitle(title), BorderLayout.NORTH);
        panel.add(editor, BorderLayout.CENTER);
        return panel;
    }

    private void stylePrimaryButton(JButton button, Color background) {
        button.setBackground(background);
        button.setForeground(Color.WHITE);
        button.setOpaque(true);
        button.setBorderPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
    }

    private void markTraffic() {
        SwingUtilities.invokeLater(() -> {
            if (trafficTimer != null && trafficTimer.isRunning()) return;
            long started = System.nanoTime();
            trafficTimer = new javax.swing.Timer(40, e -> {
                long elapsed = (System.nanoTime() - started) / 1_000_000;
                if (elapsed >= 1800) {
                    trafficTimer.stop();
                    setTabTraffic(0f);
                } else {
                    setTabTraffic(activityOpacity(elapsed));
                }
            });
            trafficTimer.setRepeats(true);
            trafficTimer.start();
        });
    }

    private static float activityOpacity(long elapsedMillis) {
        long phase = elapsedMillis % 900;
        if (phase < 160) return phase / 160f;
        if (phase < 420) return 1f;
        if (phase < 600) return 1f - (phase - 420) / 180f;
        return 0f;
    }

    private void setTabTraffic(float opacity) {
        if (!tabActivity.show(suiteTab, opacity) && opacity > 0f && !tabIndicatorFailureLogged) {
            tabIndicatorFailureLogged = true;
            api.logging().logToError("Requests Chainer: could not locate Burp's tab header to show the activity dot.");
        }
    }

    private void showTablePopup(java.awt.event.MouseEvent event) {
        if (!event.isPopupTrigger()) return;
        int row = table.rowAtPoint(event.getPoint());
        if (row >= 0 && !table.isRowSelected(row)) table.setRowSelectionInterval(row, row);
        if (table.getSelectedRowCount() == 0) return;
        JPopupMenu popup = new JPopupMenu();
        JMenuItem sendRepeater = new JMenuItem("Send to Repeater");
        sendRepeater.addActionListener(e -> sendSelectedToRepeater());
        popup.add(sendRepeater);
        if (table.getSelectedRowCount() == 1) {
            JMenuItem sendIntruder = new JMenuItem("Send target to Intruder");
            sendIntruder.addActionListener(e -> sendTargetToIntruder());
            popup.add(sendIntruder);
            JMenuItem pointRequest = new JMenuItem("Point this request");
            pointRequest.addActionListener(e -> pointSelectedRequest());
            popup.add(pointRequest);
        }
        popup.addSeparator();
        JMenuItem disable = new JMenuItem("Disable selected");
        disable.addActionListener(e -> setSelectedStepsEnabled(false));
        popup.add(disable);
        JMenuItem enable = new JMenuItem("Enable selected");
        enable.addActionListener(e -> setSelectedStepsEnabled(true));
        popup.add(enable);
        popup.addSeparator();
        JMenuItem scan = new JMenuItem("Start active scan");
        scan.addActionListener(e -> startActiveScanForSelection());
        popup.add(scan);
        popup.show(table, event.getX(), event.getY());
    }

    private void startActiveScanForSelection() {
        if (api == null) return;
        try {
            Audit audit = api.scanner().startAudit(AuditConfiguration.auditConfiguration(
                    BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
            for (int row : table.getSelectedRows()) {
                ChainStep step = steps.get(row);
                audit.addRequest(step.request());
            }
            status.setText("Active scan started for " + table.getSelectedRowCount() + " request(s).");
        } catch (Exception ex) {
            error("Cannot start active scan: " + ex.getMessage());
        }
    }

    private void openWiki() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(suiteTab),
                "Requests Chainer help", java.awt.Dialog.ModalityType.MODELESS);
        JPanel panel = new JPanel(new BorderLayout(8, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));
        panel.add(new JLabel("Requests Chainer wiki:"), BorderLayout.NORTH);
        JTextField link = new JTextField(WIKI_URL);
        link.setEditable(false);
        link.setToolTipText("Select and copy this complete URL");
        panel.add(link, BorderLayout.CENTER);
        JLabel feedback = new JLabel("Open the wiki in your browser or copy its address.");
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton open = new JButton("Open in browser");
        open.addActionListener(e -> {
            open.setEnabled(false);
            feedback.setText("Opening browser...");
            new SwingWorker<Void, Void>() {
                @Override protected Void doInBackground() throws Exception {
                    if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                        try {
                            Desktop.getDesktop().browse(URI.create(WIKI_URL));
                            return null;
                        } catch (Exception ignored) {
                            // Try the system opener below if Java's Desktop integration fails.
                        }
                    }
                    if (!System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("linux"))
                        throw new IOException("No browser opener is available");
                    Process process = new ProcessBuilder("xdg-open", WIKI_URL)
                            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                            .redirectError(ProcessBuilder.Redirect.DISCARD).start();
                    if (process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) && process.exitValue() != 0)
                        throw new IOException("xdg-open could not launch a browser");
                    return null;
                }
                @Override protected void done() {
                    open.setEnabled(true);
                    try {
                        get();
                        dialog.dispose();
                        status.setText("Requests Chainer wiki opened in your browser.");
                    } catch (Exception ex) {
                        feedback.setText("Browser unavailable. Select the URL above or use Copy link.");
                    }
                }
            }.execute();
        });
        JButton copy = new JButton("Copy link");
        copy.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(WIKI_URL), null);
            feedback.setText("Wiki link copied to clipboard.");
        });
        JButton close = new JButton("Close");
        close.addActionListener(e -> dialog.dispose());
        actions.add(feedback);
        actions.add(open);
        actions.add(copy);
        actions.add(close);
        panel.add(actions, BorderLayout.SOUTH);
        dialog.setContentPane(panel);
        dialog.setSize(800, 150);
        dialog.setLocationRelativeTo(suiteTab);
        dialog.setVisible(true);
        link.selectAll();
        link.requestFocusInWindow();
    }

    private void showSessionRuleInstructions() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(suiteTab),
                "Configure session rule", java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        JTextArea instructions = new JTextArea(
                "Requests Chainer — session rule\n\n"
                + "1. Open Settings → Sessions → Session handling rules.\n"
                + "2. Click Add.\n"
                + "3. Add the action: Invoke a Burp extension.\n"
                + "4. Select: Requests Chainer - run preceding chain.\n"
                + "5. Set the scope to: Include all URLs.\n"
                + "6. Enable the rule and click OK.\n\n"
                + "Then use Point this request for a request already in Intruder or Repeater, "
                + "or send it from Requests Chainer. Include the relevant tool in the rule scope.");
        instructions.setEditable(false);
        instructions.setOpaque(false);
        instructions.setLineWrap(true);
        instructions.setWrapStyleWord(true);
        panel.add(instructions, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton copy = new JButton("Copy action name");
        copy.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                    new StringSelection("Requests Chainer - run preceding chain"), null);
            status.setText("Session handling action name copied to clipboard.");
        });
        JButton close = new JButton("Close");
        close.addActionListener(e -> dialog.dispose());
        actions.add(copy);
        actions.add(close);
        panel.add(actions, BorderLayout.SOUTH);
        dialog.setContentPane(panel);
        dialog.setSize(600, 340);
        dialog.setLocationRelativeTo(suiteTab);
        dialog.setVisible(true);
    }

    private void showSetupAssistant() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(suiteTab),
                "Setup Requests Chainer", java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        boolean chainReady = steps.size() >= 2;
        boolean targetReady = intruderChainEnabled && intruderTargetUrl != null;
        String actionName = "Requests Chainer - run preceding chain";
        JTextArea state = new JTextArea(
                "Requests Chainer setup\n\n"
                + "Extension action:       ✓ Registered\n"
                + "Chain (2+ requests):    " + (chainReady ? "✓ Ready" : "✗ Add at least 2 requests") + "\n"
                + "Intruder target:        " + (targetReady ? "✓ Configured" : "✗ Not configured") + "\n"
                + "Session handling rule:  ? Burp must be configured manually\n\n"
                + "Next steps\n"
                + "1. Create a Session handling rule in Burp.\n"
                + "2. Add the action: Invoke a Burp extension.\n"
                + "3. Select: " + actionName + "\n"
                + "4. Set the scope and enable the rule.\n"
                + "5. Use Send target to Intruder, then start your attack.\n\n"
                + "The Test configuration button copies the action name and records a reminder in the log.");
        state.setEditable(false);
        state.setOpaque(false);
        state.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
        panel.add(state, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton test = new JButton("Test configuration");
        test.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(actionName), null);
            appendLog("Setup test: action name copied. Trigger an Intruder request to verify the Session handling rule.");
            status.setText("Setup test prepared. Run one Intruder request and check the log.");
        });
        JButton close = new JButton("Close");
        close.addActionListener(e -> dialog.dispose());
        actions.add(test);
        actions.add(close);
        panel.add(actions, BorderLayout.SOUTH);
        dialog.setContentPane(panel);
        dialog.setSize(680, 470);
        dialog.setLocationRelativeTo(suiteTab);
        dialog.setVisible(true);
    }

    private final class Menu implements ContextMenuItemsProvider {
        @Override public List<Component> provideMenuItems(ContextMenuEvent event) {
            List<Component> menu = new ArrayList<>();
            List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
            event.messageEditorRequestResponse().ifPresent(editor -> {
                if (selected.isEmpty()) selected.add(editor.requestResponse());
            });
            if (!selected.isEmpty()) {
                if (selected.size() > 1 && event.isFromTool(ToolType.PROXY))
                    java.util.Collections.reverse(selected);
                JMenuItem add = new JMenuItem("Add to Requests Chainer (oldest first from Proxy history)");
                add.addActionListener(e -> SwingUtilities.invokeLater(() -> addSteps(selected)));
                menu.add(add);
            }
            event.messageEditorRequestResponse().ifPresent(editor -> {
                if (editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE
                        && editor.selectionOffsets().isPresent()) {
                    JMenuItem capture = new JMenuItem("Requests Chainer: create variable from highlighted response value");
                    capture.addActionListener(e -> SwingUtilities.invokeLater(() -> captureSelection(editor)));
                    menu.add(capture);
                }
            });
            return menu;
        }
    }

    private void addSteps(List<HttpRequestResponse> items) {
        for (HttpRequestResponse item : items) if (item.request() != null) steps.add(new ChainStep(item));
        model.fireTableDataChanged();
        if (!steps.isEmpty()) table.setRowSelectionInterval(steps.size() - 1, steps.size() - 1);
        status.setText(steps.size() + " request(s) in chain. Use Move up/down to set execution order.");
        if (items.stream().anyMatch(item -> item.request() != null)) markTraffic();
    }

    private void storeCurrentChain() {
        saveSelected();
        namedChains.put(currentChainName, new ArrayList<>(steps));
    }
    private void switchChain(String name) {
        if (switchingChain || name == null || name.equals(currentChainName)) return;
        storeCurrentChain();
        switchingChain = true;
        steps.clear();
        steps.addAll(namedChains.getOrDefault(name, List.of()));
        currentChainName = name;
        model.fireTableDataChanged(); refreshVariables(); showSelected();
        switchingChain = false;
        status.setText("Chain selected: " + name);
    }
    private static java.time.Instant captureTime(burp.api.montoya.proxy.ProxyHttpRequestResponse item) {
        var timing = item.timingData();
        return timing != null && timing.timeRequestSent() != null
                ? timing.timeRequestSent().toInstant() : item.time().toInstant();
    }

    private record CapturedHistory(List<AutoChainFinder.Capture> captures, List<String> warnings) {}

    private CapturedHistory capturedHistory(ChainStep target, byte[] targetBytes) throws IOException {
        String origin = target.service.host() + ":" + target.service.port() + ":" + target.service.secure();
        var history = new ArrayList<>(api.proxy().history());
        history.sort(java.util.Comparator.comparing(ChainExtension::captureTime)
                .thenComparingInt(burp.api.montoya.proxy.ProxyHttpRequestResponse::id));
        int targetAt = -1;
        int equalTargets = 0;
        for (int i = history.size() - 1; i >= 0; i--) {
            var item = history.get(i);
            var service = item.httpService();
            String itemOrigin = service.host() + ":" + service.port() + ":" + service.secure();
            HttpRequest sent = item.finalRequest() == null ? item.request() : item.finalRequest();
            if (origin.equals(itemOrigin) && java.util.Arrays.equals(targetBytes, sent.toByteArray().getBytes())) {
                equalTargets++;
                if (targetAt < 0) targetAt = i;
                if (target.capturedAt != null && item.timingData() != null
                        && target.capturedAt.equals(captureTime(item))) {
                    targetAt = i; equalTargets = 1; break;
                }
            }
        }
        if (targetAt < 0) throw new IOException("Target not found in Proxy history. Add the original captured request before editing it.");
        List<AutoChainFinder.Capture> captures = new ArrayList<>();
        long totalBytes = 0;
        boolean limited = false;
        for (int i = targetAt; i >= 0; i--) {
            var item = history.get(i);
            var service = item.httpService();
            String itemOrigin = service.host() + ":" + service.port() + ":" + service.secure();
            if (!origin.equals(itemOrigin)) continue;
            if (!item.hasResponse() && i != targetAt) continue;
            HttpRequest sent = item.finalRequest() == null ? item.request() : item.finalRequest();
            byte[] request = sent.toByteArray().getBytes();
            byte[] response = item.hasResponse() ? item.response().toByteArray().getBytes() : new byte[0];
            totalBytes += request.length + response.length;
            if (captures.size() >= 2000 || totalBytes > 64L * 1024 * 1024) { limited = true; break; }
            long sentAt = captureTime(item).toEpochMilli();
            long completedAt = sentAt;
            if (item.timingData() != null) {
                var duration = item.timingData().timeBetweenRequestSentAndEndOfResponse();
                completedAt = sentAt + (duration == null ? 0 : duration.toMillis());
            }
            captures.add(new AutoChainFinder.Capture(item.id(), itemOrigin, sent.method() + " " + sent.url(),
                    request, response, sentAt, completedAt));
        }
        if (captures.isEmpty()) throw new IOException("Target exceeds the 64 MiB capture limit.");
        java.util.Collections.reverse(captures);
        List<String> warnings = new ArrayList<>();
        if (equalTargets > 1) warnings.add("Several identical targets were captured; the latest one was used.");
        if (limited) warnings.add("Analysis used the most recent 2000 same-origin entries, up to 64 MiB.");
        return new CapturedHistory(List.copyOf(captures), List.copyOf(warnings));
    }

    private void findSourceForSelection() {
        if (running || findingChain) { error("Wait for the current operation to finish"); return; }
        ChainStep target = selectedStep();
        var selection = requestEditor.selection().orElse(null);
        if (target == null || table.getSelectedRowCount() != 1 || selection == null) {
            error("Select one request, then highlight the value to find in its request editor"); return;
        }
        int start = selection.offsets().startIndexInclusive();
        int end = selection.offsets().endIndexExclusive();
        byte[] current = requestEditor.getRequest().toByteArray().getBytes();
        if (start < 0 || end <= start || end > current.length
                || !java.util.Arrays.equals(selection.contents().getBytes(), java.util.Arrays.copyOfRange(current, start, end))) {
            error("Select the value in the Raw request view so the byte range matches the request"); return;
        }
        saveSelected();
        String chainName = currentChainName;
        List<ChainStep> originalSteps = List.copyOf(steps);
        byte[] lookup = target.capturedRequestBytes == null ? current.clone() : target.capturedRequestBytes.clone();
        findingChain = true;
        status.setText("Finding prior responses for the selected value...");
        new SwingWorker<List<AutoChainFinder.SelectionSource>, Void>() {
            final List<String> warnings = new ArrayList<>();
            @Override protected List<AutoChainFinder.SelectionSource> doInBackground() throws Exception {
                CapturedHistory captured = capturedHistory(target, lookup);
                warnings.addAll(captured.warnings());
                List<AutoChainFinder.Capture> captures = new ArrayList<>(captured.captures());
                var last = captures.getLast();
                captures.set(captures.size() - 1, new AutoChainFinder.Capture(last.id(), last.origin(), last.label(),
                        current, last.response(), last.sentAt(), last.completedAt()));
                AutoChainFinder finder = new AutoChainFinder(captures);
                var matches = finder.findSelectionSources(captures.size() - 1, start, end);
                warnings.addAll(finder.discoveryWarnings());
                return matches;
            }
            @Override protected void done() {
                try {
                    var matches = get();
                    for (String warning : warnings) appendLog(LogLevel.WARNING, "DISCOVERY", warning);
                    if (matches.isEmpty()) {
                        status.setText("No source found for the selected value.");
                        error("No prior same-origin response contains this complete value in a supported extractor. Select the value without surrounding quotes. See the log for analysis limits.");
                        return;
                    }
                    if (!chainName.equals(currentChainName) || !originalSteps.equals(steps)
                            || selectedStep() != target || !java.util.Arrays.equals(current, target.requestBytes)
                            || !java.util.Arrays.equals(current, requestEditor.getRequest().toByteArray().getBytes())) {
                        error("The chain or request changed during discovery. Select the value and try again."); return;
                    }
                    var chosen = (AutoChainFinder.SelectionSource) JOptionPane.showInputDialog(suiteTab,
                            "Choose a source to insert immediately before this request.\n"
                            + "Only the highlighted range will become a variable.\n"
                            + "The source request's own dependencies will not be discovered.",
                            "Find source for selection", JOptionPane.QUESTION_MESSAGE, null,
                            matches.toArray(), matches.getFirst());
                    if (chosen == null) { status.setText("Source selection cancelled."); return; }
                    java.util.Set<String> names = new java.util.HashSet<>();
                    steps.forEach(step -> names.addAll(step.outputs.keySet()));
                    String name = "auto_selected_1";
                    for (int n = 2; names.contains(name); n++) name = "auto_selected_" + n;
                    var capture = chosen.capture();
                    HttpRequest original = HttpRequest.httpRequest(target.service, ByteArray.byteArray(capture.request()));
                    var response = burp.api.montoya.http.message.responses.HttpResponse.httpResponse(ByteArray.byteArray(capture.response()));
                    ChainStep source = new ChainStep(HttpRequestResponse.httpRequestResponse(original, response));
                    source.capturedAt = java.time.Instant.ofEpochMilli(capture.sentAt());
                    source.outputs.put(name, chosen.selector());
                    byte[] changed = ByteSplice.replace(current, start, end,
                            ("{{" + name + "|bytes}}").getBytes(StandardCharsets.US_ASCII));
                    target.setRequest(HttpRequest.httpRequest(target.service, ByteArray.byteArray(changed)));
                    int targetRow = steps.indexOf(target);
                    steps.add(targetRow, source);
                    displayedStep = null;
                    intruderChainEnabled = false; intruderTargetUrl = null;
                    model.fireTableDataChanged(); refreshVariables();
                    table.setRowSelectionInterval(targetRow + 1, targetRow + 1);
                    showSelected();
                    storeCurrentChain();
                    appendLog(LogLevel.SUCCESS, "DISCOVERY", "Inserted history #" + capture.id() + " before step "
                            + (targetRow + 2) + " · " + name + " · " + chosen.description());
                    status.setText("Source inserted; only the selected value was replaced. Review its own dependencies before running.");
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    status.setText("Source discovery failed.");
                    error("Cannot find source: " + cause.getMessage());
                } finally { findingChain = false; }
            }
        }.execute();
    }

    private void automateChainFinding() {
        if (running || findingChain) { error("Wait for the current operation to finish"); return; }
        if (table.getSelectedRowCount() != 1) { error("Select exactly one captured target request"); return; }
        saveSelected();
        ChainStep target = selectedStep();
        byte[] targetBytes = target.requestBytes.clone();
        findingChain = true;
        status.setText("Finding dependencies in captured Proxy history...");
        new SwingWorker<AutoChainFinder.Plan, Void>() {
            @Override protected AutoChainFinder.Plan doInBackground() throws Exception {
                CapturedHistory captured = capturedHistory(target, targetBytes);
                List<AutoChainFinder.Capture> captures = captured.captures();
                AutoChainFinder.Plan plan = new AutoChainFinder(captures).find(captures.size() - 1);
                List<String> warnings = new ArrayList<>(plan.warnings());
                warnings.addAll(captured.warnings());
                warnings.add("Inferred from exact reused data. Server-side state without a reused value, other origins and uncaptured traffic cannot be inferred.");
                warnings.add("When several prior responses contain a value, the most recent matching response is preferred. Review the proposed steps.");
                return new AutoChainFinder.Plan(plan.steps(), plan.links(), warnings);
            }
            @Override protected void done() {
                findingChain = false;
                try {
                    AutoChainFinder.Plan plan = get();
                    List<ChainStep> generated = new ArrayList<>();
                    for (var planned : plan.steps()) {
                        var capture = planned.capture();
                        HttpRequest original = HttpRequest.httpRequest(target.service, ByteArray.byteArray(capture.request()));
                        var response = capture.response().length == 0 ? null
                                : burp.api.montoya.http.message.responses.HttpResponse.httpResponse(ByteArray.byteArray(capture.response()));
                        ChainStep step = new ChainStep(HttpRequestResponse.httpRequestResponse(original, response));
                        step.setRequest(HttpRequest.httpRequest(target.service, ByteArray.byteArray(planned.template())));
                        step.outputs.putAll(planned.outputs());
                        generated.add(step);
                    }
                    storeCurrentChain();
                    String base = "Auto - " + target.request().method() + " " + target.request().pathWithoutQuery();
                    String name = base;
                    for (int n = 2; namedChains.containsKey(name); n++) name = base + " (" + n + ")";
                    namedChains.put(name, generated);
                    switchingChain = true;
                    try {
                        displayedStep = null;
                        steps.clear(); steps.addAll(generated);
                        currentChainName = name;
                        chainSelector.addItem(name); chainSelector.setSelectedItem(name);
                        intruderChainEnabled = false; intruderTargetUrl = null;
                        model.fireTableDataChanged(); refreshVariables();
                        table.setRowSelectionInterval(steps.size() - 1, steps.size() - 1);
                        showSelected();
                    } finally { switchingChain = false; }
                    appendLog(LogLevel.SUCCESS, "DISCOVERY", "Created " + name + " · " + generated.size() + " step(s), " + plan.links().size() + " dependency link(s)");
                    for (var link : plan.links()) appendLog(LogLevel.INFO, "DEPENDENCY", "History #" + link.sourceId()
                            + " → #" + link.consumerId() + " · " + link.variable() + " · " + link.description());
                    for (String warning : plan.warnings()) appendLog(LogLevel.WARNING, "DISCOVERY", warning);
                    status.setText("Created " + generated.size() + " steps. Review dependencies in the log, then Run chain.");
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    status.setText("Automatic chain finding failed.");
                    error("Cannot find chain: " + cause.getMessage());
                }
            }
        }.execute();
    }

    private void createNewChain() {
        String name = JOptionPane.showInputDialog(null, "Chain name:", "New chain", JOptionPane.PLAIN_MESSAGE);
        if (name == null || name.isBlank() || namedChains.containsKey(name)) return;
        storeCurrentChain();
        namedChains.put(name, new ArrayList<>());
        switchingChain = true; chainSelector.addItem(name); chainSelector.setSelectedItem(name); switchingChain = false;
        steps.clear(); currentChainName = name; model.fireTableDataChanged(); refreshVariables(); showSelected();
        status.setText("New chain created: " + name);
    }

    private void captureSelection(MessageEditorHttpRequestResponse editor) {
        HttpRequestResponse item = editor.requestResponse();
        if (!item.hasResponse()) return;
        Range range = editor.selectionOffsets().orElse(null);
        if (range == null) return;
        byte[] response = item.response().toByteArray().getBytes();
        if (range.startIndexInclusive() < 0 || range.endIndexExclusive() > response.length) {
            error("Selection is outside the response text"); return;
        }
        String value = new String(response, range.startIndexInclusive(),
                range.endIndexExclusive() - range.startIndexInclusive(), StandardCharsets.UTF_8);
        ChainStep step = selectedStep();
        if (step == null || !step.url.equals(item.request().url())) {
            step = new ChainStep(item);
            steps.add(step);
            model.fireTableDataChanged();
            table.setRowSelectionInterval(steps.size() - 1, steps.size() - 1);
        }
        createVariable(step, value, range.startIndexInclusive());
    }

    private void createVariable(ChainStep step, String selected, int selectedByteOffset) {
        if (step == null) { error("Select a request first"); return; }
        String value = selected.trim();
        int selectedAt = byteOffsetToCharIndex(step.lastResponse, selectedByteOffset);
        if (selectedAt >= 0 && !value.isEmpty()) selectedAt += selected.indexOf(value);
        if (value.isEmpty()) value = guessSelectedValue(step);
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            value = value.substring(1, value.length() - 1);
            if (selectedAt >= 0) selectedAt++;
        }
        if (value.isEmpty() && step.lastResponse.isEmpty()) { error("La réponse de cette requête est vide"); return; }
        String name = defineParameter(step, value, selectedAt);
        if (name == null) return;
        for (ChainStep existing : steps) {
            if (existing != step && existing.outputs.containsKey(name)) {
                error("Variable {{" + name + "}} already exists on another step. Delete it first or choose another name.");
                return;
            }
        }
        String selector = parameterSelector;
        try {
            int selectedRow = steps.indexOf(step);
            step.outputs.put(name, selector);
            refreshVariables();
            model.fireTableDataChanged();
            if (selectedRow >= 0 && selectedRow < steps.size()) table.setRowSelectionInterval(selectedRow, selectedRow);
            status.setText("Variable {{" + name + "}} configured for step " + (steps.indexOf(step) + 1));
        } catch (Exception ex) { error("Could not parse JSON response: " + ex.getMessage()); }
    }

    private String guessSelectedValue(ChainStep step) {
        String response = step.lastResponse;
        java.util.regex.Matcher json = java.util.regex.Pattern.compile("\\\"(?:id|token|value)\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(response);
        if (json.find()) return json.group(1);
        java.util.regex.Matcher cookie = java.util.regex.Pattern.compile("(?:ENID|SESSION|TOKEN)=([^;\\s]+)", java.util.regex.Pattern.CASE_INSENSITIVE).matcher(response);
        return cookie.find() ? cookie.group(1) : "";
    }

    private String parameterSelector;
    private String parameterNameDefault = "id";
    private String defineParameter(ChainStep step, String value, int preferredAt) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel fields = new JPanel(new java.awt.GridLayout(0, 2, 5, 5));
        JTextField name = new JTextField(parameterNameDefault);
        // Use the complete HTTP response so headers such as Set-Cookie can be captured too.
        String responseText = step.lastResponse;
        String[] delimiters = DelimiterSuggestions.bestDelimiters(responseText, value, preferredAt);
        JTextField prefix = new JTextField(delimiters[0]);
        JTextField suffix = new JTextField(delimiters[1]);
        JTextField regex = new JTextField(DelimiterSuggestions.defaultRegex(delimiters[0], delimiters[1]));
        JCheckBox caseSensitive = new JCheckBox("Case sensitive", true);
        fields.add(new JLabel("Parameter name:")); fields.add(name);
        fields.add(new JLabel("Define start (start after):")); fields.add(prefix);
        fields.add(new JLabel("Define end (end before):")); fields.add(suffix);
        panel.add(fields, BorderLayout.NORTH);
        JRadioButton startEnd = new JRadioButton("Define start and end", true);
        JRadioButton regexMode = new JRadioButton("Extract from regex group");
        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(startEnd);
        modeGroup.add(regexMode);
        JPanel modes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modes.add(startEnd); modes.add(regexMode);
        JPanel regexPanel = new JPanel(new BorderLayout(4, 4));
        regexPanel.setBorder(BorderFactory.createTitledBorder("Regex (capture group 1 is used)"));
        regexPanel.add(regex, BorderLayout.CENTER); regexPanel.add(caseSensitive, BorderLayout.SOUTH); regexPanel.setVisible(false);
        JLabel preview = new JLabel("Preview: " + value);
        preview.setBorder(BorderFactory.createTitledBorder("Preview from current response"));
        JPanel lower = new JPanel(new BorderLayout(6, 6));
        lower.add(regexPanel, BorderLayout.NORTH);
        lower.add(preview, BorderLayout.SOUTH);
        HttpResponseEditor responseSample = api.userInterface().createHttpResponseEditor();
        responseSample.setResponse(step.lastResponseBytes.length == 0
                ? burp.api.montoya.http.message.responses.HttpResponse.httpResponse(responseText)
                : burp.api.montoya.http.message.responses.HttpResponse.httpResponse(ByteArray.byteArray(step.lastResponseBytes)));
        final String[] lastSelection = {""};
        Runnable syncSelection = () -> {
            var selection = responseSample.selection().orElse(null);
            if (selection == null) return;
            String rawSelection = selection.contents().toString();
            String selectedValue = rawSelection.trim();
            if (selectedValue.isEmpty()) return;
            String selectionKey = selection.offsets().startIndexInclusive() + ":"
                    + selection.offsets().endIndexExclusive() + ":" + rawSelection;
            if (selectionKey.equals(lastSelection[0])) return;
            lastSelection[0] = selectionKey;
            int at = byteOffsetToCharIndex(responseText, selection.offsets().startIndexInclusive());
            if (at >= 0) at += rawSelection.indexOf(selectedValue);
            String[] selectedDelimiters = DelimiterSuggestions.bestDelimiters(responseText, selectedValue, at);
            prefix.setText(selectedDelimiters[0]);
            suffix.setText(selectedDelimiters[1]);
            regex.setText(DelimiterSuggestions.defaultRegex(selectedDelimiters[0], selectedDelimiters[1]));
            preview.setText("Preview: " + selectedValue);
        };
        javax.swing.Timer selectionTimer = new javax.swing.Timer(250, e -> syncSelection.run());
        selectionTimer.start();
        Component responseComponent = responseSample.uiComponent();
        responseComponent.setPreferredSize(new java.awt.Dimension(740, 230));
        lower.add(responseComponent, BorderLayout.CENTER);
        JPanel center = new JPanel(new BorderLayout(6, 6));
        center.add(modes, BorderLayout.NORTH);
        center.add(lower, BorderLayout.CENTER);
        panel.add(center, BorderLayout.CENTER);
        Runnable refresh = () -> {
            try {
                String result = regexMode.isSelected() ? ChainEngine.extract(responseText,
                        (caseSensitive.isSelected() ? "regex:" : "regexi:") + regex.getText())
                        : ChainEngine.extract(responseText, "delim:" + encode(prefix.getText(), suffix.getText()));
                preview.setText("Preview: " + result);
            } catch (Exception ex) { preview.setText("Preview: no match"); }
        };
        java.awt.event.ActionListener modeListener = e -> { prefix.setEnabled(!regexMode.isSelected()); suffix.setEnabled(!regexMode.isSelected()); regexPanel.setVisible(regexMode.isSelected()); panel.revalidate(); refresh.run(); };
        regexMode.addActionListener(modeListener);
        startEnd.addActionListener(modeListener);
        caseSensitive.addActionListener(e -> refresh.run());
        panel.setPreferredSize(new java.awt.Dimension(760, 540));
        javax.swing.event.DocumentListener listener = new javax.swing.event.DocumentListener() { public void insertUpdate(javax.swing.event.DocumentEvent e) { refresh.run(); } public void removeUpdate(javax.swing.event.DocumentEvent e) { refresh.run(); } public void changedUpdate(javax.swing.event.DocumentEvent e) { refresh.run(); } };
        prefix.getDocument().addDocumentListener(listener); suffix.getDocument().addDocumentListener(listener); regex.getDocument().addDocumentListener(listener);
        int result = JOptionPane.showConfirmDialog(null, panel, "Define custom parameter", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        selectionTimer.stop();
        if (result != JOptionPane.OK_OPTION) return null;
        if (!name.getText().matches("[A-Za-z][A-Za-z0-9_]*")) { error("Invalid variable name"); return null; }
        if (regexMode.isSelected()) parameterSelector = (caseSensitive.isSelected() ? "regex:" : "regexi:") + regex.getText();
        else parameterSelector = "delim:" + encode(prefix.getText(), suffix.getText());
        return name.getText();
    }

    private JTextPane createColoredResponsePane(String text) {
        JTextPane pane = new JTextPane();
        pane.setEditable(false);
        StyledDocument document = pane.getStyledDocument();
        try { document.insertString(0, text, null); } catch (Exception ignored) { }
        Style header = pane.addStyle("header", null); StyleConstants.setForeground(header, new Color(0x2367A8));
        Style json = pane.addStyle("json", null); StyleConstants.setForeground(json, new Color(0x8A3B12));
        int split = text.indexOf("\r\n\r\n"); if (split < 0) split = text.indexOf("\n\n");
        if (split >= 0) document.setCharacterAttributes(0, split, header, false);
        int bodyStart = split < 0 ? 0 : split + (text.startsWith("\r\n", split) ? 4 : 2);
        if (bodyStart < text.length()) document.setCharacterAttributes(bodyStart, text.length() - bodyStart, json, false);
        return pane;
    }

    private String encode(String prefix, String suffix) {
        return java.util.Base64.getUrlEncoder().encodeToString(prefix.getBytes(StandardCharsets.UTF_8)) + "." + java.util.Base64.getUrlEncoder().encodeToString(suffix.getBytes(StandardCharsets.UTF_8));
    }

    private void insertVariable() {
        if (selectedStep() == null) { error("Select a destination request first"); return; }
        String name = (String) variableBox.getSelectedItem();
        if (name == null || name.isBlank()) { error("No variable matches the search"); return; }
        String replacement = variablePlaceholder(name);
        byte[] original = requestEditor.getRequest().toByteArray().getBytes();
        byte[] replacementBytes = ByteArray.byteArray(replacement).getBytes();
        byte[] updated;
        java.util.Optional<burp.api.montoya.ui.Selection> selectedRequest = requestEditor.selection();
        if (selectedRequest.isPresent() && selectedRequest.get().offsets().startIndexInclusive() < selectedRequest.get().offsets().endIndexExclusive()) {
            burp.api.montoya.core.Range range = selectedRequest.get().offsets();
            updated = ByteSplice.replace(original, range.startIndexInclusive(), range.endIndexExclusive(), replacementBytes);
        } else {
            int caret = requestEditor.caretPosition();
            updated = ByteSplice.replace(original, caret, caret, replacementBytes);
        }
        HttpRequest updatedRequest = HttpRequest.httpRequest(selectedStep().service, ByteArray.byteArray(updated));
        requestEditor.setRequest(updatedRequest);
        selectedStep().setRequest(updatedRequest);
    }

    private void saveSelected() {
        ChainStep step = selectedStep();
        if (step != null && requestEditor.isModified()) {
            HttpRequest updated = requestEditor.getRequest();
            if (!java.util.Arrays.equals(updated.toByteArray().getBytes(), step.requestBytes))
                requestUndo.push(step.requestBytes.clone());
            step.setRequest(updated);
        }
    }
    private void undoRequestEdit() {
        ChainStep step = selectedStep();
        if (step == null || requestUndo.isEmpty()) return;
        step.setRequest(HttpRequest.httpRequest(step.service, ByteArray.byteArray(requestUndo.pop())));
        requestEditor.setRequest(step.request());
        status.setText("Last request edit undone.");
    }
    private void refreshVariables() {
        String filter = variableSearch.getText().toLowerCase();
        String current = (String) variableBox.getSelectedItem();
        variableBox.removeAllItems();
        steps.stream().flatMap(s -> s.outputs.keySet().stream()).distinct()
                .filter(v -> v.toLowerCase().contains(filter)).forEach(variableBox::addItem);
        if (current != null) variableBox.setSelectedItem(current);
    }
    private String selectedText(HttpResponseEditor area) { return area.selection().map(s -> s.contents().toString()).orElse(""); }
    private int selectedOffset(HttpResponseEditor area) {
        return area.selection().map(s -> s.offsets().startIndexInclusive()).orElse(-1);
    }
    private static int byteOffsetToCharIndex(String text, int byteOffset) {
        if (byteOffset < 0) return -1;
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (byteOffset > bytes.length) return -1;
        return new String(bytes, 0, byteOffset, StandardCharsets.UTF_8).length();
    }
    private ChainStep selectedStep() { int row = table.getSelectedRow(); return row < 0 || row >= steps.size() ? null : steps.get(row); }
    private void showSelected() {
        if (displayedStep != null && requestEditor.isModified()) displayedStep.setRequest(requestEditor.getRequest());
        ChainStep step = selectedStep();
        displayedStep = step;
        if (step != null) {
            requestEditor.setRequest(step.request());
            responseEditor.setResponse(step.lastResponseBytes.length == 0
                    ? burp.api.montoya.http.message.responses.HttpResponse.httpResponse(step.lastResponse)
                    : burp.api.montoya.http.message.responses.HttpResponse.httpResponse(ByteArray.byteArray(step.lastResponseBytes)));
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest());
            responseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse());
        }
        requestEditor.setCaretPosition(0); responseEditor.setCaretPosition(0);
    }
    private void move(int delta) {
        int index = table.getSelectedRow(), target = index + delta;
        if (index < 0 || target < 0 || target >= steps.size()) return;
        saveSelected();
        java.util.Collections.swap(steps, index, target);
        model.fireTableDataChanged(); table.setRowSelectionInterval(target, target);
    }
    private void deleteVariable() {
        String name = (String) variableBox.getSelectedItem();
        if (name == null || name.isBlank()) { error("Select a variable first"); return; }
        int removed = 0;
        for (ChainStep step : steps) if (step.outputs.remove(name) != null) removed++;
        refreshVariables(); model.fireTableDataChanged();
        status.setText(removed == 0 ? "Variable not found." : "Variable {{" + name + "}} deleted.");
    }
    private void editVariable() {
        String name = (String) variableBox.getSelectedItem();
        if (name == null || name.isBlank()) { error("Select a variable first"); return; }
        for (ChainStep step : steps) {
            if (step.outputs.containsKey(name)) {
                parameterNameDefault = name;
                createVariable(step, selectedText(responseEditor), selectedOffset(responseEditor));
                parameterNameDefault = "id";
                return;
            }
        }
        error("Variable not found");
    }
    private void replaceAcrossRequests() {
        JPanel panel = new JPanel(new java.awt.GridLayout(2, 2, 6, 6));
        String selected = requestEditor.selection().map(s -> s.contents().toString()).orElse("");
        JTextField search = new JTextField(selected);
        JTextField replacement = new JTextField();
        panel.add(new JLabel("Search:")); panel.add(search);
        panel.add(new JLabel("Replace with:")); panel.add(replacement);
        int result = JOptionPane.showConfirmDialog(null, panel, "Replace in all requests", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION || search.getText().isEmpty()) return;
        saveSelected();
        int changed = 0;
        for (ChainStep step : steps) {
            String updated = step.requestTemplate.replace(search.getText(), replacement.getText());
            if (!updated.equals(step.requestTemplate)) { step.setTemplateText(updated); changed++; }
        }
        displayedStep = null;
        model.fireTableDataChanged();
        showSelected();
        status.setText("Replaced '" + search.getText() + "' in " + changed + " request(s).");
    }
    private void propagateVariableHeader() {
        String variable = (String) variableBox.getSelectedItem();
        if (variable == null || variable.isBlank()) { error("Select a variable first"); return; }
        JPanel panel = new JPanel(new java.awt.GridLayout(1, 2, 6, 6));
        JTextField header = new JTextField("Authorization");
        panel.add(new JLabel("Header name:")); panel.add(header);
        if (JOptionPane.showConfirmDialog(null, panel, "Use variable in all headers", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION) return;
        if (!header.getText().matches("[A-Za-z0-9-]+")) { error("Invalid header name"); return; }
        saveSelected();
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("(?im)^(" + java.util.regex.Pattern.quote(header.getText()) + "\\s*:\\s*)[^\\r\\n]+$");
        int changed = 0;
        for (ChainStep step : steps) {
            String updated = pattern.matcher(step.requestTemplate).replaceAll("$1" + java.util.regex.Matcher.quoteReplacement(variablePlaceholder(variable)));
            if (!updated.equals(step.requestTemplate)) { step.setTemplateText(updated); changed++; }
        }
        displayedStep = null; model.fireTableDataChanged(); showSelected();
        status.setText("Header " + header.getText() + " now uses {{" + variable + "}} in " + changed + " request(s).");
    }
    private String b64(String value) { return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8)); }
    private String variablePlaceholder(String name) {
        boolean binary = steps.stream().anyMatch(step -> step.outputs.getOrDefault(name, "").startsWith("auto:"));
        return "{{" + name + (binary ? "|bytes" : "") + "}}";
    }
    private String unb64(String value) { return new String(java.util.Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8); }
    private void saveChain() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Requests Chainer chains");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Requests Chainer files (*.rchain)", "rchain"));
        if (lastChainDirectory != null) chooser.setCurrentDirectory(lastChainDirectory);
        chooser.setSelectedFile(new java.io.File(currentChainName.replaceAll("[^A-Za-z0-9._-]", "_") + ".rchain"));
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        java.io.File selectedFile = chooser.getSelectedFile();
        if (!selectedFile.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".rchain"))
            selectedFile = new java.io.File(selectedFile.getParentFile(), selectedFile.getName() + ".rchain");
        lastChainDirectory = selectedFile.getParentFile();
        try (java.io.BufferedWriter out = java.nio.file.Files.newBufferedWriter(selectedFile.toPath(), StandardCharsets.UTF_8)) {
            storeCurrentChain(); out.write("REQUESTS-CHAINS-1\n");
            for (Map.Entry<String, List<ChainStep>> chain : namedChains.entrySet()) {
                out.write("C\t" + b64(chain.getKey()) + "\n");
                for (ChainStep step : chain.getValue()) {
                out.write("S\t" + b64(step.service.host()) + "\t" + step.service.port() + "\t" + step.service.secure()
                        + "\t" + b64(step.requestTemplate) + "\t" + step.enabled + "\t"
                        + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(step.requestBytes) + "\n");
                for (Map.Entry<String, String> output : step.outputs.entrySet()) out.write("V\t" + b64(output.getKey()) + "\t" + b64(output.getValue()) + "\n");
                out.write("E\n");
                }
            }
            status.setText("Chains saved: " + selectedFile.getName());
        } catch (Exception ex) { error("Cannot save chain: " + ex.getMessage()); }
    }
    private void loadChain() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Load Requests Chainer chains");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Requests Chainer files (*.rchain, legacy)", "rchain", "chain"));
        if (lastChainDirectory != null) chooser.setCurrentDirectory(lastChainDirectory);
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
        lastChainDirectory = chooser.getSelectedFile().getParentFile();
        try {
            List<String> lines = java.nio.file.Files.readAllLines(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8);
            if (lines.isEmpty() || !(lines.get(0).equals("REQUESTS-CHAINS-1") || lines.get(0).equals("REQUESTS-CHAIN-1"))) throw new IOException("Invalid chain file");
            boolean legacy = lines.get(0).equals("REQUESTS-CHAIN-1");
            namedChains.clear();
            if (legacy) namedChains.put("Default", new ArrayList<>());
            List<ChainStep> loaded = new ArrayList<>(); ChainStep current = null;
            for (String line : lines.subList(1, lines.size())) {
                String[] parts = line.split("\\t", -1);
                if (parts[0].equals("C")) {
                    String name = unb64(parts[1]); namedChains.put(name, new ArrayList<>()); current = null;
                } else if (parts[0].equals("S")) {
                    HttpService service = HttpService.httpService(unb64(parts[1]), Integer.parseInt(parts[2]), Boolean.parseBoolean(parts[3]));
                    current = new ChainStep(service, unb64(parts[4]));
                    if (parts.length > 5) current.enabled = Boolean.parseBoolean(parts[5]);
                    if (parts.length > 6) current.setRequest(HttpRequest.httpRequest(service,
                            ByteArray.byteArray(java.util.Base64.getUrlDecoder().decode(parts[6]))));
                    String active = legacy ? "Default" : namedChains.keySet().stream().reduce((a, b) -> b).orElse("Default");
                    namedChains.get(active).add(current);
                } else if (parts[0].equals("V") && current != null) current.outputs.put(unb64(parts[1]), unb64(parts[2]));
            }
            namedChains.keySet().forEach(n -> { if (((javax.swing.DefaultComboBoxModel<String>) chainSelector.getModel()).getIndexOf(n) < 0) chainSelector.addItem(n); });
            if (!namedChains.isEmpty()) { currentChainName = namedChains.keySet().iterator().next(); steps.clear(); steps.addAll(namedChains.get(currentChainName)); chainSelector.setSelectedItem(currentChainName); }
            model.fireTableDataChanged(); refreshVariables();
            if (!steps.isEmpty()) table.setRowSelectionInterval(0, 0);
            status.setText("Chain loaded: " + chooser.getSelectedFile().getName());
        } catch (Exception ex) { error("Cannot load chain: " + ex.getMessage()); }
    }
    private void removeSelected() {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) return;
        for (int i = selected.length - 1; i >= 0; i--) steps.remove(selected[i]);
        model.fireTableDataChanged();
        if (!steps.isEmpty()) table.setRowSelectionInterval(Math.min(selected[0], steps.size() - 1), Math.min(selected[0], steps.size() - 1));
        else showSelected();
    }

    private void setSelectedStepsEnabled(boolean enabled) {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) return;
        for (int row : selected) steps.get(row).enabled = enabled;
        refreshPointedTargetState();
        model.fireTableRowsUpdated(selected[0], selected[selected.length - 1]);
        status.setText(selected.length + " request(s) " + (enabled ? "enabled" : "disabled") + " in the chain.");
    }

    private void refreshPointedTargetState() {
        if (intruderTargetUrl == null) return;
        if (intruderTargetIndex <= 0 || intruderTargetIndex >= steps.size()
                || !steps.get(intruderTargetIndex).enabled) {
            intruderChainEnabled = false;
            return;
        }
        try {
            ChainStep target = steps.get(intruderTargetIndex);
            intruderChainEnabled = intruderTargetUrl.equals(target.request().url());
        } catch (Exception ex) {
            intruderChainEnabled = false;
        }
    }

    private static List<ChainStep> enabledSteps(List<ChainStep> candidates) {
        return candidates.stream().filter(step -> step.enabled).toList();
    }

    private HttpRequest renderedStepRequest(ChainStep step, String rendered) {
        return rendered.equals(step.requestTemplate)
                ? step.request() : HttpRequest.httpRequest(step.service, rendered);
    }

    private HttpRequest renderedStepRequest(ChainStep step, String rendered, Map<String, String> variables) {
        if (rendered.equals(step.requestTemplate)) return step.request();
        byte[] bytes = ByteTemplate.render(step.requestBytes, variables,
                value -> ByteArray.byteArray(value).getBytes());
        return HttpRequest.httpRequest(step.service, ByteArray.byteArray(bytes));
    }

    private void runChain() {
        if (running || findingChain) { error("A chain operation is already running"); return; }
        if (steps.isEmpty()) {
            status.setText("Nothing to run: add at least one request from Proxy history.");
            appendLog(LogLevel.WARNING, "CHAIN", "No requests to run");
            return;
        }
        saveSelected();
        List<ChainStep> snapshot = enabledSteps(List.copyOf(steps));
        if (snapshot.isEmpty()) {
            status.setText("Nothing to run: enable at least one request in the chain.");
            appendLog(LogLevel.WARNING, "CHAIN", "All requests are disabled");
            return;
        }
        int repetitions = ((Number) repetitionCount.getValue()).intValue();
        running = true;
        appendLog(LogLevel.INFO, "CHAIN",
                "Starting " + repetitions + " run(s) · " + snapshot.size() + " step(s) each");
        status.setText("Running " + snapshot.size() + " request(s)...");
        new SwingWorker<Void, LogEntry>() {
            @Override protected Void doInBackground() throws Exception {
                List<ChainEngine.Step> definitions = snapshot.stream()
                        .map(step -> new ChainEngine.Step(step.requestTemplate, Map.copyOf(step.outputs))).toList();
                for (int run = 1; run <= repetitions; run++) {
                    final int runNumber = run;
                    long runStarted = System.nanoTime();
                    publish(new LogEntry(LogLevel.INFO, "RUN " + runNumber + "/" + repetitions, "Started"));
                    ChainEngine.run(definitions, (index, raw, variables) -> {
                        ChainStep step = snapshot.get(index);
                        HttpRequest request = renderedStepRequest(step, raw, variables);
                        long stepStarted = System.nanoTime();
                        HttpRequestResponse result = api.http().sendRequest(request);
                        long elapsed = (System.nanoTime() - stepStarted) / 1_000_000;
                        if (!result.hasResponse()) {
                            publish(new LogEntry(LogLevel.ERROR, "STEP " + (index + 1),
                                    "No response · " + elapsed + " ms · " + step.url));
                            return null;
                        }
                        int httpStatus = result.response().statusCode();
                        publish(new LogEntry(httpStatus < 400 ? LogLevel.SUCCESS : LogLevel.ERROR,
                                "STEP " + (index + 1), "Run " + runNumber + "/" + repetitions
                                + " · HTTP " + httpStatus + " · " + elapsed + " ms · " + step.url));
                        step.lastResponseBytes = result.response().toByteArray().getBytes();
                        step.lastResponse = result.response().toString();
                        step.lastResponseBody = result.response().bodyToString();
                        return new ChainEngine.Response(httpStatus, step.lastResponse, result.response().toByteArray().getBytes());
                    }, message -> {
                        if (message.contains(" = "))
                            publish(new LogEntry(LogLevel.INFO, "VARIABLE", "Run " + runNumber + "/" + repetitions
                                    + " · " + message));
                    });
                    publish(new LogEntry(LogLevel.SUCCESS, "RUN " + runNumber + "/" + repetitions,
                            "Completed · " + ((System.nanoTime() - runStarted) / 1_000_000) + " ms"));
                }
                return null;
            }
            @Override protected void process(List<LogEntry> messages) {
                for (LogEntry message : messages) appendLog(message);
                showSelected();
            }
            @Override protected void done() {
                running = false;
                try {
                    get();
                    status.setText("Chain finished successfully.");
                    appendLog(LogLevel.SUCCESS, "CHAIN", "All runs completed");
                }
                catch (Exception ex) {
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    status.setText("Chain stopped: " + cause.getMessage());
                    appendLog(LogLevel.ERROR, "CHAIN", "Stopped · " + cause.getMessage());
                }
            }
        }.execute();
    }

    private void runWithWordlist() {
        if (running || findingChain) { error("A chain operation is already running"); return; }
        int target = table.getSelectedRow();
        if (target < 0 || target >= steps.size()) { error("Select the chain request that will receive the wordlist"); return; }
        if (!steps.get(target).enabled) { error("Enable the selected request before using a wordlist"); return; }
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
        try {
            List<String> payloads = java.nio.file.Files.readAllLines(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8)
                    .stream().filter(line -> !line.isEmpty()).toList();
            if (payloads.isEmpty()) { error("The wordlist is empty"); return; }
            saveSelected();
            ChainStep targetStep = steps.get(target);
            List<ChainStep> snapshot = enabledSteps(List.copyOf(steps));
            running = true;
            appendLog("Starting wordlist run: " + payloads.size() + " payload(s), target step " + (target + 1));
            new SwingWorker<Void, String>() {
                @Override protected Void doInBackground() throws Exception {
                    for (int n = 0; n < payloads.size(); n++) {
                        String payload = payloads.get(n);
                        List<ChainEngine.Step> definitions = new ArrayList<>();
                        for (int i = 0; i < snapshot.size(); i++) {
                            String template = snapshot.get(i).requestTemplate;
                            if (snapshot.get(i) == targetStep) template = injectWordlist(template, payload);
                            definitions.add(new ChainEngine.Step(template, Map.copyOf(snapshot.get(i).outputs)));
                        }
                        final int runNumber = n + 1;
                        ChainEngine.run(definitions, (index, raw) -> {
                            ChainStep step = snapshot.get(index);
                            HttpRequestResponse result = api.http().sendRequest(renderedStepRequest(step, raw));
                            if (!result.hasResponse()) return null;
                            step.lastResponseBytes = result.response().toByteArray().getBytes();
                        step.lastResponse = result.response().toString();
                            step.lastResponseBody = result.response().bodyToString();
                            return new ChainEngine.Response(result.response().statusCode(), step.lastResponse, result.response().toByteArray().getBytes());
                        }, message -> publish("Payload " + runNumber + ": " + message));
                    }
                    return null;
                }
                @Override protected void process(List<String> messages) { for (String message : messages) appendLog(message); }
                @Override protected void done() { running = false; try { get(); status.setText("Wordlist run finished."); } catch (Exception ex) { status.setText("Wordlist run stopped: " + ex.getCause()); } }
            }.execute();
        } catch (Exception ex) { error("Cannot read wordlist: " + ex.getMessage()); }
    }

    private void sendSelectedToRepeater() {
        int[] selected = table.getSelectedRows();
        if (selected.length == 0) { error("Select a request first"); return; }
        saveSelected();
        try {
            for (int row : selected) {
                ChainStep step = steps.get(row);
                api.repeater().sendToRepeater(
                        step.request(),
                        "Requests Chainer - " + currentChainName + " #" + (row + 1));
            }
            if (selected.length == 1) {
                ChainStep target = steps.get(selected[0]);
                if (target.enabled) {
                    pointToStep(target);
                    status.setText("Request sent to Repeater. Include Repeater in the session rule scope to run preceding steps.");
                } else {
                    status.setText("Request sent to Repeater. Enable this step to use it as a session-rule target.");
                }
            } else {
                status.setText(selected.length + " requests sent to Repeater. Select one target to link the session rule.");
            }
        } catch (Exception ex) {
            error("Cannot send request to Repeater: " + ex.getMessage());
        }
    }

    private void pointSelectedRequest() {
        if (table.getSelectedRowCount() != 1) {
            error("Select exactly one target request in the chain");
            return;
        }
        ChainStep step = selectedStep();
        if (!step.enabled) {
            error("Enable this request before pointing it as the session-rule target");
            return;
        }
        if (steps.indexOf(step) == 0) {
            error("Select a request after at least one preceding chain step");
            return;
        }
        saveSelected();
        try {
            pointToStep(step);
            status.setText("Target pointed: step " + (intruderTargetIndex + 1)
                    + ". The session rule will run preceding steps for this URL in Repeater or Intruder.");
        } catch (Exception ex) {
            error("Cannot point to this request: " + ex.getMessage());
        }
    }

    private void pointToStep(ChainStep step) {
        if (!step.enabled) throw new IllegalStateException("Enable this request before pointing it as a target");
        int index = steps.indexOf(step);
        String url = step.request().url();
        intruderTargetIndex = index;
        intruderTargetUrl = url;
        intruderChainEnabled = index > 0 && step.enabled;
    }

    private void sendTargetToIntruder() {
        ChainStep step = selectedStep();
        if (step == null) { error("Select the target request first"); return; }
        saveSelected();
        try {
            api.intruder().sendToIntruder(step.request(), "Requests Chainer");
            if (step.enabled) {
                pointToStep(step);
                status.setText("Target sent. Add 'Requests Chainer - run preceding chain' to a Burp Session handling rule for Intruder.");
            } else {
                status.setText("Request sent to Intruder. Enable this step to use it as a session-rule target.");
            }
        } catch (Exception ex) { error("Cannot send request to Intruder: " + ex.getMessage()); }
    }

    private final class ChainSessionAction implements SessionHandlingAction {
        @Override public String name() { return "Requests Chainer - run preceding chain"; }
        @Override public ActionResult performAction(SessionHandlingActionData data) {
            if (!intruderChainEnabled || intruderTargetUrl == null || !intruderTargetUrl.equals(data.request().url()))
                return ActionResult.actionResult(data.request());
            long started = System.nanoTime();
            try {
                List<ChainStep> before = enabledSteps(List.copyOf(steps.subList(0, intruderTargetIndex)));
                List<ChainEngine.Step> definitions = before.stream().map(s -> new ChainEngine.Step(s.requestTemplate, Map.copyOf(s.outputs))).toList();
                Map<String, String> variables = ChainEngine.run(definitions, (index, raw, resolvedVariables) -> {
                    ChainStep step = before.get(index);
                    long stepStarted = System.nanoTime();
                    HttpRequestResponse result = api.http().sendRequest(renderedStepRequest(step, raw, resolvedVariables));
                    long elapsed = (System.nanoTime() - stepStarted) / 1_000_000;
                    if (!result.hasResponse()) {
                        appendLog(LogLevel.ERROR, "SESSION", "Step " + (index + 1) + " · no response · " + elapsed + " ms");
                        return null;
                    }
                    int httpStatus = result.response().statusCode();
                    appendLog(httpStatus < 400 ? LogLevel.SUCCESS : LogLevel.ERROR, "SESSION",
                            "Step " + (index + 1) + " · HTTP " + httpStatus + " · " + elapsed + " ms · " + step.url);
                    step.lastResponseBytes = result.response().toByteArray().getBytes();
                        step.lastResponse = result.response().toString();
                    step.lastResponseBody = result.response().bodyToString();
                    return new ChainEngine.Response(httpStatus, step.lastResponse, result.response().toByteArray().getBytes());
                }, message -> {
                    if (message.contains(" = ")) appendLog(LogLevel.INFO, "VARIABLE", "Session · " + message);
                });
                appendLog(LogLevel.SUCCESS, "SESSION",
                        "Target prepared · " + ((System.nanoTime() - started) / 1_000_000) + " ms");
                String targetTemplate = data.request().toString();
                String renderedTarget = Template.renderHttpRequest(targetTemplate, variables);
                return ActionResult.actionResult(renderedTarget.equals(targetTemplate) ? data.request()
                        : HttpRequest.httpRequest(data.request().httpService(), ByteArray.byteArray(
                                ByteTemplate.render(data.request().toByteArray().getBytes(), variables,
                                        value -> ByteArray.byteArray(value).getBytes()))));
            } catch (Exception ex) {
                api.logging().logToError("Session chain failed: " + ex.getMessage());
                appendLog(LogLevel.ERROR, "SESSION", "Preparation failed · " + ex.getMessage());
                return ActionResult.actionResult(data.request());
            }
        }
    }

    private final class IntruderChainHandler implements HttpHandler {
        @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            if (!intruderChainEnabled || !request.toolSource().isFromTool(ToolType.INTRUDER)
                    || intruderChainRunning.get()
                    || intruderTargetUrl == null || !intruderTargetUrl.equals(request.url()))
                return RequestToBeSentAction.continueWith(request);
            try {
                intruderChainRunning.set(true);
                long started = System.nanoTime();
                List<ChainStep> before = enabledSteps(List.copyOf(steps.subList(0, intruderTargetIndex)));
                List<ChainEngine.Step> definitions = before.stream()
                        .map(step -> new ChainEngine.Step(step.requestTemplate, Map.copyOf(step.outputs))).toList();
                Map<String, String> variables = ChainEngine.run(definitions, (index, raw, resolvedVariables) -> {
                    long stepStarted = System.nanoTime();
                    ChainStep step = before.get(index);
                    HttpRequestResponse result = api.http().sendRequest(renderedStepRequest(step, raw, resolvedVariables));
                    if (!result.hasResponse()) return null;
                    step.lastResponseBytes = result.response().toByteArray().getBytes();
                        step.lastResponse = result.response().toString();
                    step.lastResponseBody = result.response().bodyToString();
                    appendLog("Intruder chain step " + (index + 1) + " took " + ((System.nanoTime() - stepStarted) / 1_000_000) + " ms");
                    return new ChainEngine.Response(result.response().statusCode(), step.lastResponse, result.response().toByteArray().getBytes());
                }, message -> appendLog("Intruder chain: " + message));
                appendLog("Intruder chain preparation took " + ((System.nanoTime() - started) / 1_000_000) + " ms");
                String targetTemplate = request.toString();
                String renderedTarget = Template.renderHttpRequest(targetTemplate, variables);
                return RequestToBeSentAction.continueWith(renderedTarget.equals(targetTemplate) ? request
                        : HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(
                                ByteTemplate.render(request.toByteArray().getBytes(), variables,
                                        value -> ByteArray.byteArray(value).getBytes()))));
            } catch (Exception ex) {
                api.logging().logToError("Intruder chain failed: " + ex.getMessage());
                return RequestToBeSentAction.continueWith(request);
            } finally { intruderChainRunning.set(false); }
        }
        @Override public ResponseReceivedAction handleHttpResponseReceived(burp.api.montoya.http.handler.HttpResponseReceived response) {
            return ResponseReceivedAction.continueWith(response);
        }
    }

    private String injectWordlist(String request, String payload) {
        if (request.contains("{{WORDLIST}}")) return request.replace("{{WORDLIST}}", payload);
        int start = request.indexOf('§');
        int end = start < 0 ? -1 : request.indexOf('§', start + 1);
        if (start >= 0 && end > start) return request.substring(0, start) + payload + request.substring(end + 1);
        throw new IllegalArgumentException("Mark the target value with {{WORDLIST}} or §value§");
    }

    private static final java.time.format.DateTimeFormatter LOG_TIME =
            java.time.format.DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private record LogEntry(LogLevel level, String source, String message, java.time.LocalTime time) {
        LogEntry(LogLevel level, String source, String message) {
            this(level, source, message, java.time.LocalTime.now());
        }
    }

    private enum LogLevel {
        INFO("INFO", new Color(0x3974A8)),
        SUCCESS("OK", new Color(0x35865B)),
        WARNING("WARN", new Color(0xA96B16)),
        ERROR("ERROR", new Color(0xC74843));

        final String label;
        final Color color;
        LogLevel(String label, Color color) { this.label = label; this.color = color; }
    }

    private void appendLog(String message) {
        appendLog(LogLevel.INFO, "EVENT", message);
    }

    private void appendLog(LogLevel level, String source, String message) {
        appendLog(new LogEntry(level, source, message));
    }

    private void appendLog(LogEntry entry) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> appendLog(entry));
            return;
        }
        String time = entry.time().format(LOG_TIME);
        String singleLine = entry.message().replace("\r", "\\r").replace("\n", "\\n");
        if (singleLine.length() > 500)
            singleLine = singleLine.substring(0, 500) + "… (+" + (singleLine.length() - 500) + " chars)";
        StyledDocument document = log.getStyledDocument();
        try {
            Style muted = log.getStyle("log-muted");
            if (muted == null) {
                muted = log.addStyle("log-muted", null);
                Color mutedColor = javax.swing.UIManager.getColor("Label.disabledForeground");
                StyleConstants.setForeground(muted, mutedColor != null ? mutedColor : Color.GRAY);
            }
            Style levelStyle = log.getStyle("log-" + entry.level().label);
            if (levelStyle == null) {
                levelStyle = log.addStyle("log-" + entry.level().label, null);
                StyleConstants.setForeground(levelStyle, entry.level().color);
                StyleConstants.setBold(levelStyle, true);
            }
            document.insertString(document.getLength(), time + "  ", muted);
            document.insertString(document.getLength(), String.format("%-5s", entry.level().label) + "  ", levelStyle);
            document.insertString(document.getLength(), String.format("%-10s", entry.source()) + "  ", muted);
            document.insertString(document.getLength(), singleLine + "\n", null);
            if (document.getLength() > 250_000) {
                int excess = document.getLength() - 200_000;
                String beginning = document.getText(0, Math.min(document.getLength(), excess + 1024));
                int lastLine = beginning.lastIndexOf('\n');
                if (lastLine >= 0) document.remove(0, lastLine + 1);
            }
            log.setCaretPosition(document.getLength());
        } catch (javax.swing.text.BadLocationException ex) {
            api.logging().logToError("Activity log update failed: " + ex.getMessage());
        }
    }

    private void saveActivityLog() {
        String contents = log.getText();
        if (contents.isEmpty()) {
            status.setText("The activity log is empty.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save Requests Chainer activity log");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Log files (*.log)", "log"));
        if (lastLogDirectory != null) chooser.setCurrentDirectory(lastLogDirectory);
        String timestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
        chooser.setSelectedFile(new java.io.File("requests-chainer-" + timestamp + ".log"));
        if (chooser.showSaveDialog(suiteTab) != JFileChooser.APPROVE_OPTION) return;
        java.io.File file = chooser.getSelectedFile();
        if (!file.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".log"))
            file = new java.io.File(file.getParentFile(), file.getName() + ".log");
        if (file.exists() && JOptionPane.showConfirmDialog(suiteTab,
                "Replace the existing file " + file.getName() + "?", "Overwrite activity log",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) != JOptionPane.YES_OPTION) return;
        try {
            java.nio.file.Files.writeString(file.toPath(), contents, StandardCharsets.UTF_8);
            lastLogDirectory = file.getParentFile();
            status.setText("Activity log saved: " + file.getName());
            status.setToolTipText(file.getAbsolutePath());
        } catch (IOException ex) {
            error("Cannot save activity log: " + ex.getMessage());
        }
    }
    private void error(String message) { JOptionPane.showMessageDialog(null, message, "Requests Chainer", JOptionPane.ERROR_MESSAGE); }

    /** FlowLayout whose preferred height follows the available width instead of clipping buttons. */
    private static final class WrapLayout extends FlowLayout {
        WrapLayout(int align, int hgap, int vgap) { super(align, hgap, vgap); }
        @Override public java.awt.Dimension preferredLayoutSize(java.awt.Container target) {
            synchronized (target.getTreeLock()) {
                int width = target.getWidth();
                if (width <= 0) width = 900;
                java.awt.Insets insets = target.getInsets();
                int max = width - insets.left - insets.right - getHgap() * 2;
                int rowWidth = 0, rowHeight = 0, totalHeight = getVgap();
                for (Component component : target.getComponents()) {
                    if (!component.isVisible()) continue;
                    java.awt.Dimension size = component.getPreferredSize();
                    if (rowWidth > 0 && rowWidth + getHgap() + size.width > max) {
                        totalHeight += rowHeight + getVgap(); rowWidth = 0; rowHeight = 0;
                    }
                    rowWidth += (rowWidth == 0 ? 0 : getHgap()) + size.width;
                    rowHeight = Math.max(rowHeight, size.height);
                }
                totalHeight += rowHeight + getVgap();
                return new java.awt.Dimension(width, totalHeight + insets.top + insets.bottom);
            }
        }
    }

    private final class StepTable extends AbstractTableModel {
        @Override public int getRowCount() { return steps.size(); }
        @Override public int getColumnCount() { return 4; }
        @Override public String getColumnName(int column) { return switch (column) { case 0 -> "Enabled"; case 1 -> "Order"; case 2 -> "Request"; default -> "Variables from response"; }; }
        @Override public Class<?> getColumnClass(int column) { return column == 0 ? Boolean.class : column == 1 ? Integer.class : String.class; }
        @Override public boolean isCellEditable(int row, int column) { return column == 0; }
        @Override public void setValueAt(Object value, int row, int column) {
            if (column != 0 || !(value instanceof Boolean enabled)) return;
            steps.get(row).enabled = enabled;
            refreshPointedTargetState();
            fireTableRowsUpdated(row, row);
        }
        @Override public Object getValueAt(int row, int column) {
            ChainStep step = steps.get(row);
            return switch (column) { case 0 -> step.enabled; case 1 -> row + 1; case 2 -> step.url; default -> step.outputs.toString(); };
        }
    }
}
