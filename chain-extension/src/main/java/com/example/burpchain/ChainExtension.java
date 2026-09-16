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
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Color;
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
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JFileChooser;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.AbstractTableModel;

public final class ChainExtension implements BurpExtension {
    private MontoyaApi api;
    private Component suiteTab;
    private volatile boolean intruderChainEnabled;
    private volatile String intruderTargetUrl;
    private volatile int intruderTargetIndex;
    private final List<ChainStep> steps = new ArrayList<>();
    private final StepTable model = new StepTable();
    private final JTable table = new JTable(model);
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final javax.swing.JTextArea log = new javax.swing.JTextArea(5, 80);
    private final JLabel status = new JLabel("Select requests in Proxy history, then right-click > Add to Requests Chainer.");
    private volatile boolean running;
    private ChainStep displayedStep;
    private final JComboBox<String> variableBox = new JComboBox<>();
    private final JTextField variableSearch = new JTextField(12);
    private final JSpinner repetitionCount = new JSpinner(new SpinnerNumberModel(1, 1, 1000, 1));
    private final Deque<String> requestUndo = new ArrayDeque<>();

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Requests Chainer");
        suiteTab = buildPanel();
        api.userInterface().registerSuiteTab("Requests Chainer", suiteTab);
        api.userInterface().registerContextMenuItemsProvider(new Menu());
        api.http().registerHttpHandler(new IntruderChainHandler());
    }

    private Component buildPanel() {
        JPanel root = new JPanel(new BorderLayout(6, 6));
        root.setMinimumSize(new java.awt.Dimension(900, 600));
        root.setPreferredSize(new java.awt.Dimension(1200, 800));
        JPanel buttons = new JPanel(new WrapLayout(FlowLayout.LEFT, 5, 2));
        JButton up = new JButton("Move up");
        JButton down = new JButton("Move down");
        JButton remove = new JButton("Remove");
        JButton save = new JButton("Save request edit");
        JButton variable = new JButton("Variable from response selection");
        JButton insert = new JButton("Insert variable");
        JButton intruder = new JButton("Send target to Intruder");
        JButton saveChain = new JButton("Save chain");
        JButton loadChain = new JButton("Load chain");
        JButton deleteVariable = new JButton("Delete variable");
        JButton editVariable = new JButton("Edit variable");
        variable.setBackground(new Color(0x2F75B5));
        variable.setForeground(Color.WHITE);
        variable.setOpaque(true);
        variable.setBorderPainted(false);
        JButton run = new JButton("Run chain");
        run.setToolTipText("Execute the requests in the table in order");
        JButton clear = new JButton("Clear chain");
        buttons.add(run); buttons.add(clear); buttons.add(up); buttons.add(down); buttons.add(remove);
        buttons.add(save); buttons.add(variable); buttons.add(insert); buttons.add(intruder);
        buttons.add(saveChain); buttons.add(loadChain); buttons.add(deleteVariable); buttons.add(editVariable);
        run.setBackground(new Color(0xE8752A));
        run.setForeground(Color.WHITE);
        run.setOpaque(true);
        run.setBorderPainted(false);
        JPanel variableBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        variableBar.add(new JLabel("Select the variable to insert:"));
        variableBar.add(variableSearch);
        variableBar.add(variableBox);
        variableBar.add(new JLabel("Select the number of chain runs:"));
        variableBar.add(new JLabel("Runs:"));
        repetitionCount.setToolTipText("Number of complete chain executions (1-1000)");
        variableBar.add(repetitionCount);
        JPanel top = new JPanel();
        top.setLayout(new javax.swing.BoxLayout(top, javax.swing.BoxLayout.Y_AXIS));
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        variableBar.setAlignmentX(Component.LEFT_ALIGNMENT);
        top.add(buttons);
        top.add(variableBar);
        root.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override public void componentResized(java.awt.event.ComponentEvent e) {
                buttons.revalidate();
                top.revalidate();
                root.revalidate();
            }
        });
        root.add(top, BorderLayout.NORTH);
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();
        log.setEditable(false);
        // Montoya's native editors provide their own scrolling and syntax coloring.
        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        editors.setResizeWeight(0.5);
        JSplitPane main = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), editors);
        main.setResizeWeight(0.25);
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(status, BorderLayout.NORTH);
        bottom.add(new JScrollPane(log), BorderLayout.CENTER);
        JSplitPane content = new JSplitPane(JSplitPane.VERTICAL_SPLIT, main, bottom);
        content.setResizeWeight(0.82);
        content.setOneTouchExpandable(true);
        root.add(content, BorderLayout.CENTER);
        root.setFocusable(true);
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control R"), "requests-chainer-run");
        root.getActionMap().put("requests-chainer-run", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { runChain(); }
        });
        root.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke("control Z"), "requests-chainer-undo");
        root.getActionMap().put("requests-chainer-undo", new AbstractAction() {
            @Override public void actionPerformed(java.awt.event.ActionEvent event) { undoRequestEdit(); }
        });
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelected(); });
        table.setCellSelectionEnabled(true);
        up.addActionListener(e -> move(-1));
        down.addActionListener(e -> move(1));
        remove.addActionListener(e -> removeSelected());
        save.addActionListener(e -> { saveSelected(); status.setText("Request edit saved for the selected chain step."); });
        variable.addActionListener(e -> createVariable(selectedStep(), selectedText(responseEditor)));
        insert.addActionListener(e -> insertVariable());
        intruder.addActionListener(e -> sendTargetToIntruder());
        saveChain.addActionListener(e -> saveChain());
        loadChain.addActionListener(e -> loadChain());
        deleteVariable.addActionListener(e -> deleteVariable());
        editVariable.addActionListener(e -> editVariable());
        run.addActionListener(e -> runChain());
        clear.addActionListener(e -> { steps.clear(); model.fireTableDataChanged(); showSelected(); log.setText(""); status.setText("Chain cleared. Add requests from Proxy history."); });
        variableSearch.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { refreshVariables(); }
            public void removeUpdate(DocumentEvent e) { refreshVariables(); }
            public void changedUpdate(DocumentEvent e) { refreshVariables(); }
        });
        return root;
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
            step.outputs.put(name, selector);
            refreshVariables();
            model.fireTableDataChanged();
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
        java.util.Optional<String> selectedRequest = requestEditor.selection().map(s -> s.contents().toString());
        if (selectedRequest.isPresent() && !selectedRequest.get().isEmpty()) {
            int start = current.indexOf(selectedRequest.get());
            updated = start < 0 ? current : current.substring(0, start) + replacement
                    + current.substring(start + selectedRequest.get().length());
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
    private String b64(String value) { return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8)); }
    private String unb64(String value) { return new String(java.util.Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8); }
    private void saveChain() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(null) != JFileChooser.APPROVE_OPTION) return;
        try (java.io.BufferedWriter out = java.nio.file.Files.newBufferedWriter(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8)) {
            saveSelected(); out.write("REQUESTS-CHAIN-1\n");
            for (ChainStep step : steps) {
                out.write("S\t" + b64(step.service.host()) + "\t" + step.service.port() + "\t" + step.service.secure() + "\t" + b64(step.requestTemplate) + "\n");
                for (Map.Entry<String, String> output : step.outputs.entrySet()) out.write("V\t" + b64(output.getKey()) + "\t" + b64(output.getValue()) + "\n");
                out.write("E\n");
            }
            status.setText("Chain saved: " + chooser.getSelectedFile().getName());
        } catch (Exception ex) { error("Cannot save chain: " + ex.getMessage()); }
    }
    private void loadChain() {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showOpenDialog(null) != JFileChooser.APPROVE_OPTION) return;
        try {
            List<String> lines = java.nio.file.Files.readAllLines(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8);
            if (lines.isEmpty() || !lines.get(0).equals("REQUESTS-CHAIN-1")) throw new IOException("Invalid chain file");
            List<ChainStep> loaded = new ArrayList<>(); ChainStep current = null;
            for (String line : lines.subList(1, lines.size())) {
                String[] parts = line.split("\\t", -1);
                if (parts[0].equals("S")) {
                    HttpService service = HttpService.httpService(unb64(parts[1]), Integer.parseInt(parts[2]), Boolean.parseBoolean(parts[3]));
                    current = new ChainStep(service, unb64(parts[4])); loaded.add(current);
                } else if (parts[0].equals("V") && current != null) current.outputs.put(unb64(parts[1]), unb64(parts[2]));
            }
            steps.clear(); steps.addAll(loaded); model.fireTableDataChanged(); refreshVariables();
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
            log.append("Run chain ignored: the chain is empty.\n");
            log.setCaretPosition(log.getDocument().getLength());
            return;
        }
        saveSelected();
        List<ChainStep> snapshot = List.copyOf(steps);
        int repetitions = ((Number) repetitionCount.getValue()).intValue();
        running = true;
        log.append("Starting " + repetitions + " run(s), " + snapshot.size() + " step(s) each...\n");
        log.setCaretPosition(log.getDocument().getLength());
        status.setText("Running " + snapshot.size() + " request(s)...");
        new SwingWorker<Void, String>() {
            @Override protected Void doInBackground() throws Exception {
                List<ChainEngine.Step> definitions = snapshot.stream()
                        .map(step -> new ChainEngine.Step(step.requestTemplate, Map.copyOf(step.outputs))).toList();
                for (int run = 1; run <= repetitions; run++) {
                    final int runNumber = run;
                    publish("Run " + runNumber + "/" + repetitions + " started");
                    ChainEngine.run(definitions, (index, raw) -> {
                        ChainStep step = snapshot.get(index);
                        HttpRequest request = HttpRequest.httpRequest(step.service, raw);
                        HttpRequestResponse result = api.http().sendRequest(request);
                        if (!result.hasResponse()) return null;
                        step.lastResponse = result.response().toString();
                        step.lastResponse = result.response().toString();
                        step.lastResponseBody = result.response().bodyToString();
                        return new ChainEngine.Response(result.response().statusCode(), step.lastResponse);
                    }, message -> publish("Run " + runNumber + ": " + message));
                }
                return null;
            }
            @Override protected void process(List<String> messages) {
                for (String message : messages) log.append(message + "\n");
                showSelected();
            }
            @Override protected void done() {
                running = false;
                try { get(); status.setText("Chain finished successfully."); }
                catch (Exception ex) {
                    Throwable cause = ex.getCause() == null ? ex : ex.getCause();
                    status.setText("Chain stopped: " + cause.getMessage());
                    log.append(status.getText() + "\n");
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
            log.append("Starting wordlist run: " + payloads.size() + " payload(s), target step " + (target + 1) + "\n");
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
                @Override protected void process(List<String> messages) { for (String message : messages) log.append(message + "\n"); }
                @Override protected void done() { running = false; try { get(); status.setText("Wordlist run finished."); } catch (Exception ex) { status.setText("Wordlist run stopped: " + ex.getCause()); } }
            }.execute();
        } catch (Exception ex) { error("Cannot read wordlist: " + ex.getMessage()); }
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
            status.setText("Target sent to Intruder. The " + intruderTargetIndex + " preceding chain step(s) run before each Intruder request.");
        } catch (Exception ex) { error("Cannot send request to Intruder: " + ex.getMessage()); }
    }

    private final class IntruderChainHandler implements HttpHandler {
        @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
            if (!intruderChainEnabled || !request.toolSource().isFromTool(ToolType.INTRUDER)
                    || intruderTargetUrl == null || !intruderTargetUrl.equals(request.url()))
                return RequestToBeSentAction.continueWith(request);
            try {
                List<ChainStep> before = List.copyOf(steps.subList(0, intruderTargetIndex));
                List<ChainEngine.Step> definitions = before.stream()
                        .map(step -> new ChainEngine.Step(step.requestTemplate, Map.copyOf(step.outputs))).toList();
                Map<String, String> variables = ChainEngine.run(definitions, (index, raw) -> {
                    ChainStep step = before.get(index);
                    HttpRequestResponse result = api.http().sendRequest(HttpRequest.httpRequest(step.service, raw));
                    if (!result.hasResponse()) return null;
                    step.lastResponse = result.response().toString();
                    step.lastResponseBody = result.response().bodyToString();
                    return new ChainEngine.Response(result.response().statusCode(), step.lastResponse);
                }, message -> log.append("Intruder chain: " + message + "\n"));
                return RequestToBeSentAction.continueWith(HttpRequest.httpRequest(request.httpService(),
                        Template.renderHttpRequest(request.toString(), variables)));
            } catch (Exception ex) {
                api.logging().logToError("Intruder chain failed: " + ex.getMessage());
                return RequestToBeSentAction.continueWith(request);
            }
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
