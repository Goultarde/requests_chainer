package com.example.burpchain;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
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
import java.awt.FlowLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
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
    private ChainStep displayedStep;
    private final JComboBox<String> variableBox = new JComboBox<>();
    private final JComboBox<String> chainSelector = new JComboBox<>();
    private final JTextField variableSearch = new JTextField(12);
    private final JSpinner repetitionCount = new JSpinner(new SpinnerNumberModel(1, 1, 1000, 1));
    private final Deque<String> requestUndo = new ArrayDeque<>();
    private java.io.File lastChainDirectory;
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
        JButton remove = new JButton("Remove");
        JButton save = new JButton("Save request edit");
        JButton variable = new JButton("Variable from response selection");
        JButton insert = new JButton("Insert variable");
        JButton intruder = new JButton("Send target to Intruder");
        JButton repeater = new JButton("Send to Repeater");
        JButton sessionRule = new JButton("⚙ Configure Intruder session rule");
        JButton saveChain = new JButton("Save chains");
        JButton loadChain = new JButton("Load chains");
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
        run.setToolTipText("Execute all requests in order (Ctrl+Alt+R)");
        intruder.setToolTipText("Use the selected request as the Intruder target (Ctrl+I)");
        repeater.setToolTipText("Open the selected request(s) in Burp Repeater (Ctrl+R)");
        variable.setToolTipText("Select a value in the response editor to create a reusable variable");
        variableSearch.setToolTipText("Filter the variable list");
        variableBox.setToolTipText("Select a variable to insert or manage");
        chainSelector.setToolTipText("Choose the chain to edit");
        chainSelector.setPrototypeDisplayValue("A chain with a long name");
        variableBox.setPrototypeDisplayValue("A long variable name");
        repetitionCount.setToolTipText("Number of complete chain executions (1-1000)");

        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));
        Color separator = javax.swing.UIManager.getColor("Separator.foreground");
        top.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0,
                separator != null ? separator : Color.GRAY));
        top.add(toolbarRow("CHAIN", new JLabel("Name:"), chainSelector, newChain, saveChain, loadChain));
        top.add(toolbarRow("RUN", run, new JLabel("Runs:"), repetitionCount, clear, intruder, repeater, sessionRule));
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
        table.getColumnModel().getColumn(0).setPreferredWidth(55);
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(600);
        table.getColumnModel().getColumn(2).setPreferredWidth(250);
        JPanel stepsPanel = new JPanel(new BorderLayout(4, 4));
        JPanel stepsHeader = new JPanel(new BorderLayout());
        stepsHeader.add(sectionTitle("Chain steps"), BorderLayout.WEST);
        JPanel stepActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        stepActions.add(up); stepActions.add(down); stepActions.add(remove);
        stepsHeader.add(stepActions, BorderLayout.EAST);
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
        JButton clearLog = new JButton("Clear log");
        clearLog.addActionListener(e -> log.setText(""));
        JPanel logActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        logActions.add(copyLog);
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
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mousePressed(java.awt.event.MouseEvent e) { showTablePopup(e); }
            @Override public void mouseReleased(java.awt.event.MouseEvent e) { showTablePopup(e); }
        });
        up.addActionListener(e -> move(-1));
        down.addActionListener(e -> move(1));
        remove.addActionListener(e -> removeSelected());
        save.addActionListener(e -> { saveSelected(); status.setText("Request edit saved for the selected chain step."); });
        variable.addActionListener(e -> createVariable(selectedStep(), selectedText(responseEditor)));
        insert.addActionListener(e -> insertVariable());
        intruder.addActionListener(e -> sendTargetToIntruder());
        repeater.addActionListener(e -> sendSelectedToRepeater());
        sessionRule.addActionListener(e -> showSessionRuleInstructions());
        saveChain.addActionListener(e -> saveChain());
        loadChain.addActionListener(e -> loadChain());
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
        }
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
                audit.addRequest(HttpRequest.httpRequest(step.service, step.requestTemplate));
            }
            status.setText("Active scan started for " + table.getSelectedRowCount() + " request(s).");
        } catch (Exception ex) {
            error("Cannot start active scan: " + ex.getMessage());
        }
    }

    private void showSessionRuleInstructions() {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(suiteTab),
                "Configure Intruder session rule", java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        JTextArea instructions = new JTextArea(
                "Requests Chainer — Intruder session rule\n\n"
                + "1. Open Settings → Sessions → Session handling rules.\n"
                + "2. Click Add.\n"
                + "3. Add the action: Invoke a Burp extension.\n"
                + "4. Select: Requests Chainer - run preceding chain.\n"
                + "5. Set the scope to: Include all URLs.\n"
                + "6. Enable the rule and click OK.\n\n"
                + "Then use Send target to Intruder in Requests Chainer before starting Intruder.");
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
        createVariable(step, value);
    }

    private void createVariable(ChainStep step, String selected) {
        if (step == null) { error("Select a request first"); return; }
        String value = selected.trim();
        if (value.isEmpty()) value = guessSelectedValue(step);
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\""))
            value = value.substring(1, value.length() - 1);
        if (value.isEmpty() && step.lastResponse.isEmpty()) { error("La réponse de cette requête est vide"); return; }
        String name = defineParameter(step, value);
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
    private String defineParameter(ChainStep step, String value) {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel fields = new JPanel(new java.awt.GridLayout(0, 2, 5, 5));
        JTextField name = new JTextField(parameterNameDefault);
        // Use the complete HTTP response so headers such as Set-Cookie can be captured too.
        String responseText = step.lastResponse;
        String[] delimiters = bestDelimiters(responseText, value);
        JTextField prefix = new JTextField(delimiters[0]);
        JTextField suffix = new JTextField(delimiters[1]);
        JTextField regex = new JTextField(defaultRegex(responseText, value, delimiters[0], delimiters[1]));
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
        responseSample.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(responseText));
        int selectedAt = responseText.indexOf(value);
        Runnable syncSelection = () -> {
            String selectedValue = responseSample.selection().map(s -> s.contents().toString()).orElse("").trim();
            if (selectedValue.isEmpty()) return;
            String[] selectedDelimiters = bestDelimiters(responseText, selectedValue);
            prefix.setText(selectedDelimiters[0]);
            suffix.setText(selectedDelimiters[1]);
            regex.setText(defaultRegex(responseText, selectedValue, selectedDelimiters[0], selectedDelimiters[1]));
            preview.setText("Preview: " + selectedValue);
        };
        if (selectedAt >= 0) syncSelection.run();
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

    private String[] defaultDelimiters(String body, String value) {
        int at = body.indexOf(value);
        if (at < 0) return new String[]{"", ""};
        int line = Math.max(body.lastIndexOf("\n", at), body.lastIndexOf("\r", at));
        int semi = body.lastIndexOf(';', at);
        int start;
        if (semi < line) {
            start = line + 1;
        } else {
            start = semi + 1;
            while (start < at && Character.isWhitespace(body.charAt(start))) start++;
        }
        String prefix = body.substring(start, at);
        int lineEnd = body.indexOf('\n', at + value.length());
        if (lineEnd < 0) lineEnd = body.length();
        int contentEnd = lineEnd > 0 && body.charAt(lineEnd - 1) == '\r' ? lineEnd - 1 : lineEnd;
        int end = body.indexOf(';', at + value.length());
        if (end < 0 || end > lineEnd) end = -1;
        String suffix = "";
        if (end >= 0) {
            int equals = body.indexOf('=', end + 1);
            suffix = equals >= 0 ? body.substring(end, equals + 1) : body.substring(end);
        } else {
            suffix = body.substring(at + value.length(), contentEnd);
        }
        return new String[]{prefix, suffix};
    }
    private String[] bestDelimiters(String response, String value) {
        // Algorithm adapted from ExtendedMacro's ExtStringCreator (MIT license).
        int at = response.indexOf(value);
        if (at < 0 || value.isEmpty()) return defaultDelimiters(response, value);
        int before = Math.max(0, at - 8), after = Math.min(response.length(), at + value.length() + 8);
        while (true) {
            String prefix = response.substring(before, at);
            String suffix = response.substring(at + value.length(), after);
            int start = prefix.isEmpty() ? 0 : response.indexOf(prefix);
            int end = start < 0 ? -1 : response.indexOf(suffix, start + prefix.length());
            String extracted = start < 0 || end < 0 ? "" : response.substring(start + prefix.length(), end);
            if (value.equals(extracted)) return new String[]{prefix, suffix};
            int oldBefore = before, oldAfter = after;
            before = Math.max(0, before - 8);
            after = Math.min(response.length(), after + 8);
            if (before == oldBefore && after == oldAfter) break;
        }
        return defaultDelimiters(response, value);
    }
    private String escapeRegex(String value) { return value.replaceAll("([\\\\.\\[\\]{}()*+?^$|])", "\\\\$1"); }
    private String defaultRegex(String response, String value, String prefix, String suffix) {
        String[] best = bestDelimiters(response, value);
        return escapeRegex(best[0]) + "(.*?)" + escapeRegex(best[1]);
    }
    private String encode(String prefix, String suffix) {
        return java.util.Base64.getUrlEncoder().encodeToString(prefix.getBytes(StandardCharsets.UTF_8)) + "." + java.util.Base64.getUrlEncoder().encodeToString(suffix.getBytes(StandardCharsets.UTF_8));
    }

    private void insertVariable() {
        if (selectedStep() == null) { error("Select a destination request first"); return; }
        String name = (String) variableBox.getSelectedItem();
        if (name == null || name.isBlank()) { error("No variable matches the search"); return; }
        String current = requestEditor.getRequest().toString();
        String replacement = "{{" + name + "}}";
        String updated;
        java.util.Optional<burp.api.montoya.ui.Selection> selectedRequest = requestEditor.selection();
        if (selectedRequest.isPresent() && selectedRequest.get().offsets().startIndexInclusive() < selectedRequest.get().offsets().endIndexExclusive()) {
            byte[] original = requestEditor.getRequest().toByteArray().getBytes();
            burp.api.montoya.core.Range range = selectedRequest.get().offsets();
            byte[] replacementBytes = replacement.getBytes(StandardCharsets.UTF_8);
            byte[] result = new byte[original.length - (range.endIndexExclusive() - range.startIndexInclusive()) + replacementBytes.length];
            System.arraycopy(original, 0, result, 0, range.startIndexInclusive());
            System.arraycopy(replacementBytes, 0, result, range.startIndexInclusive(), replacementBytes.length);
            System.arraycopy(original, range.endIndexExclusive(), result, range.startIndexInclusive() + replacementBytes.length, original.length - range.endIndexExclusive());
            updated = new String(result, StandardCharsets.UTF_8);
        } else {
            int caret = requestEditor.caretPosition();
            updated = current.substring(0, caret) + replacement + current.substring(caret);
        }
        requestEditor.setRequest(HttpRequest.httpRequest(selectedStep().service, updated));
        saveSelected();
    }

    private void saveSelected() {
        ChainStep step = selectedStep();
        if (step != null) {
            String updated = requestEditor.getRequest().toString();
            if (!updated.equals(step.requestTemplate)) requestUndo.push(step.requestTemplate);
            step.requestTemplate = updated;
        }
    }
    private void undoRequestEdit() {
        ChainStep step = selectedStep();
        if (step == null || requestUndo.isEmpty()) return;
        step.requestTemplate = requestUndo.pop();
        requestEditor.setRequest(HttpRequest.httpRequest(step.service, step.requestTemplate));
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
    private ChainStep selectedStep() { int row = table.getSelectedRow(); return row < 0 || row >= steps.size() ? null : steps.get(row); }
    private void showSelected() {
        if (displayedStep != null) displayedStep.requestTemplate = requestEditor.getRequest().toString();
        ChainStep step = selectedStep();
        displayedStep = step;
        if (step != null) {
            requestEditor.setRequest(HttpRequest.httpRequest(step.service, step.requestTemplate));
            responseEditor.setResponse(burp.api.montoya.http.message.responses.HttpResponse.httpResponse(step.lastResponse));
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
                createVariable(step, selectedText(responseEditor));
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
            if (!updated.equals(step.requestTemplate)) { step.requestTemplate = updated; changed++; }
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
            String updated = pattern.matcher(step.requestTemplate).replaceAll("$1{{" + java.util.regex.Matcher.quoteReplacement(variable) + "}}");
            if (!updated.equals(step.requestTemplate)) { step.requestTemplate = updated; changed++; }
        }
        displayedStep = null; model.fireTableDataChanged(); showSelected();
        status.setText("Header " + header.getText() + " now uses {{" + variable + "}} in " + changed + " request(s).");
    }
    private String b64(String value) { return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8)); }
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
                out.write("S\t" + b64(step.service.host()) + "\t" + step.service.port() + "\t" + step.service.secure() + "\t" + b64(step.requestTemplate) + "\n");
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

    private void runChain() {
        if (running) { error("A chain is already running"); return; }
        if (steps.isEmpty()) {
            status.setText("Nothing to run: add at least one request from Proxy history.");
            appendLog(LogLevel.WARNING, "CHAIN", "No requests to run");
            return;
        }
        saveSelected();
        List<ChainStep> snapshot = List.copyOf(steps);
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
                    ChainEngine.run(definitions, (index, raw) -> {
                        ChainStep step = snapshot.get(index);
                        HttpRequest request = HttpRequest.httpRequest(step.service, raw);
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
                        step.lastResponse = result.response().toString();
                        step.lastResponseBody = result.response().bodyToString();
                        return new ChainEngine.Response(httpStatus, step.lastResponse);
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
        if (running) { error("A chain is already running"); return; }
        int target = table.getSelectedRow();
        if (target < 0 || target >= steps.size()) { error("Select the chain request that will receive the wordlist"); return; }
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
        try {
            List<String> payloads = java.nio.file.Files.readAllLines(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8)
                    .stream().filter(line -> !line.isEmpty()).toList();
            if (payloads.isEmpty()) { error("The wordlist is empty"); return; }
            saveSelected();
            List<ChainStep> snapshot = List.copyOf(steps);
            running = true;
            appendLog("Starting wordlist run: " + payloads.size() + " payload(s), target step " + (target + 1));
            new SwingWorker<Void, String>() {
                @Override protected Void doInBackground() throws Exception {
                    for (int n = 0; n < payloads.size(); n++) {
                        String payload = payloads.get(n);
                        List<ChainEngine.Step> definitions = new ArrayList<>();
                        for (int i = 0; i < snapshot.size(); i++) {
                            String template = snapshot.get(i).requestTemplate;
                            if (i == target) template = injectWordlist(template, payload);
                            definitions.add(new ChainEngine.Step(template, Map.copyOf(snapshot.get(i).outputs)));
                        }
                        final int runNumber = n + 1;
                        ChainEngine.run(definitions, (index, raw) -> {
                            ChainStep step = snapshot.get(index);
                            HttpRequestResponse result = api.http().sendRequest(HttpRequest.httpRequest(step.service, raw));
                            if (!result.hasResponse()) return null;
                            step.lastResponse = result.response().toString();
                            step.lastResponseBody = result.response().bodyToString();
                            return new ChainEngine.Response(result.response().statusCode(), step.lastResponse);
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
                        HttpRequest.httpRequest(step.service, step.requestTemplate),
                        "Requests Chainer - " + currentChainName + " #" + (row + 1));
            }
            if (selected.length == 1) {
                ChainStep target = steps.get(selected[0]);
                intruderTargetUrl = target.url;
                intruderTargetIndex = selected[0];
                intruderChainEnabled = intruderTargetIndex > 0;
                status.setText("Request sent to Repeater. Include Repeater in the session rule scope to run preceding steps.");
            } else {
                status.setText(selected.length + " requests sent to Repeater. Select one target to link the session rule.");
            }
        } catch (Exception ex) {
            error("Cannot send request to Repeater: " + ex.getMessage());
        }
    }

    private void sendTargetToIntruder() {
        ChainStep step = selectedStep();
        if (step == null) { error("Select the target request first"); return; }
        saveSelected();
        try {
            intruderTargetUrl = step.url;
            intruderTargetIndex = steps.indexOf(step);
            intruderChainEnabled = intruderTargetIndex > 0;
            api.intruder().sendToIntruder(HttpRequest.httpRequest(step.service, step.requestTemplate), "Requests Chainer");
            status.setText("Target sent. Add 'Requests Chainer - run preceding chain' to a Burp Session handling rule for Intruder.");
        } catch (Exception ex) { error("Cannot send request to Intruder: " + ex.getMessage()); }
    }

    private final class ChainSessionAction implements SessionHandlingAction {
        @Override public String name() { return "Requests Chainer - run preceding chain"; }
        @Override public ActionResult performAction(SessionHandlingActionData data) {
            if (!intruderChainEnabled || intruderTargetUrl == null || !intruderTargetUrl.equals(data.request().url()))
                return ActionResult.actionResult(data.request());
            long started = System.nanoTime();
            try {
                List<ChainStep> before = List.copyOf(steps.subList(0, intruderTargetIndex));
                List<ChainEngine.Step> definitions = before.stream().map(s -> new ChainEngine.Step(s.requestTemplate, Map.copyOf(s.outputs))).toList();
                Map<String, String> variables = ChainEngine.run(definitions, (index, raw) -> {
                    ChainStep step = before.get(index);
                    long stepStarted = System.nanoTime();
                    HttpRequestResponse result = api.http().sendRequest(HttpRequest.httpRequest(step.service, raw));
                    long elapsed = (System.nanoTime() - stepStarted) / 1_000_000;
                    if (!result.hasResponse()) {
                        appendLog(LogLevel.ERROR, "SESSION", "Step " + (index + 1) + " · no response · " + elapsed + " ms");
                        return null;
                    }
                    int httpStatus = result.response().statusCode();
                    appendLog(httpStatus < 400 ? LogLevel.SUCCESS : LogLevel.ERROR, "SESSION",
                            "Step " + (index + 1) + " · HTTP " + httpStatus + " · " + elapsed + " ms · " + step.url);
                    step.lastResponse = result.response().toString();
                    step.lastResponseBody = result.response().bodyToString();
                    return new ChainEngine.Response(httpStatus, step.lastResponse);
                }, message -> {
                    if (message.contains(" = ")) appendLog(LogLevel.INFO, "VARIABLE", "Session · " + message);
                });
                appendLog(LogLevel.SUCCESS, "SESSION",
                        "Target prepared · " + ((System.nanoTime() - started) / 1_000_000) + " ms");
                return ActionResult.actionResult(HttpRequest.httpRequest(data.request().httpService(),
                        Template.renderHttpRequest(data.request().toString(), variables)));
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
                List<ChainStep> before = List.copyOf(steps.subList(0, intruderTargetIndex));
                List<ChainEngine.Step> definitions = before.stream()
                        .map(step -> new ChainEngine.Step(step.requestTemplate, Map.copyOf(step.outputs))).toList();
                Map<String, String> variables = ChainEngine.run(definitions, (index, raw) -> {
                    long stepStarted = System.nanoTime();
                    ChainStep step = before.get(index);
                    HttpRequestResponse result = api.http().sendRequest(HttpRequest.httpRequest(step.service, raw));
                    if (!result.hasResponse()) return null;
                    step.lastResponse = result.response().toString();
                    step.lastResponseBody = result.response().bodyToString();
                    appendLog("Intruder chain step " + (index + 1) + " took " + ((System.nanoTime() - stepStarted) / 1_000_000) + " ms");
                    return new ChainEngine.Response(result.response().statusCode(), step.lastResponse);
                }, message -> appendLog("Intruder chain: " + message));
                appendLog("Intruder chain preparation took " + ((System.nanoTime() - started) / 1_000_000) + " ms");
                return RequestToBeSentAction.continueWith(HttpRequest.httpRequest(request.httpService(),
                        Template.renderHttpRequest(request.toString(), variables)));
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
        @Override public int getColumnCount() { return 3; }
        @Override public String getColumnName(int column) { return switch (column) { case 0 -> "Order"; case 1 -> "Request"; default -> "Variables from response"; }; }
        @Override public Object getValueAt(int row, int column) {
            ChainStep step = steps.get(row);
            return switch (column) { case 0 -> row + 1; case 1 -> step.url; default -> step.outputs.toString(); };
        }
    }
}
