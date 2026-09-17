package com.example.burpchain;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.RenderingHints;
import java.awt.AlphaComposite;
import javax.swing.Icon;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JLayeredPane;
import javax.swing.JRootPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

/** Shows activity on a tab without replacing Burp's custom tab controls. */
final class TabActivityIndicator {
    private static final String PADDING_KEY = "requestsChainer.activityDotPadding";
    private float opacity = 1f;
    private final Icon dot = new Icon() {
        @Override public int getIconWidth() { return 10; }
        @Override public int getIconHeight() { return 10; }
        @Override public void paintIcon(Component component, Graphics graphics, int x, int y) {
            Graphics2D g = (Graphics2D) graphics.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setComposite(AlphaComposite.SrcOver.derive(opacity));
            g.setColor(new Color(0xE8752A));
            g.fillOval(x + 1, y + 1, 8, 8);
            g.dispose();
        }
    };

    private Tab tab;
    private Icon originalIcon;
    private boolean showing;
    private Component activeHeader;
    private JRootPane activeRoot;
    private final java.awt.event.ComponentAdapter repositionListener = new java.awt.event.ComponentAdapter() {
        @Override public void componentResized(java.awt.event.ComponentEvent event) { reposition(); }
        @Override public void componentMoved(java.awt.event.ComponentEvent event) { reposition(); }
        @Override public void componentShown(java.awt.event.ComponentEvent event) { reposition(); }
    };
    private final java.awt.event.HierarchyListener hierarchyListener = event -> reposition();
    private final JComponent overlay = new JComponent() {
        @Override public boolean contains(int x, int y) { return false; }
        @Override protected void paintComponent(Graphics graphics) {
            dot.paintIcon(this, graphics, 0, 0);
        }
    };

    boolean show(Component content, boolean visible) {
        return show(content, visible ? 1f : 0f);
    }

    boolean show(Component content, float newOpacity) {
        Tab next = findTab(content);
        if (next == null) return false;
        if (!next.equals(tab)) {
            restore();
            tab = next;
            originalIcon = next.icon();
        }
        opacity = Math.max(0f, Math.min(1f, newOpacity));
        if (opacity > 0f) {
            if (next.customHeader() != null && next.label() == null) {
                if (!showOverlay(next.customHeader())) return false;
            } else {
                next.setIcon(dot);
            }
            showing = true;
        } else {
            restore();
        }
        return true;
    }

    private void restore() {
        if (showing && tab != null && tab.icon() == dot) tab.setIcon(originalIcon);
        if (overlay.getParent() != null) {
            Container parent = overlay.getParent();
            parent.remove(overlay);
            parent.repaint();
        }
        if (activeHeader != null) {
            activeHeader.removeComponentListener(repositionListener);
            activeHeader.removeHierarchyListener(hierarchyListener);
        }
        if (activeRoot != null) activeRoot.removeComponentListener(repositionListener);
        activeHeader = null;
        activeRoot = null;
        showing = false;
    }

    private boolean showOverlay(Component header) {
        JRootPane root = SwingUtilities.getRootPane(header);
        if (root == null) return false;
        if (activeHeader != header || activeRoot != root) {
            if (activeHeader != null) {
                activeHeader.removeComponentListener(repositionListener);
                activeHeader.removeHierarchyListener(hierarchyListener);
            }
            if (activeRoot != null) activeRoot.removeComponentListener(repositionListener);
            activeHeader = header;
            activeRoot = root;
            header.addComponentListener(repositionListener);
            header.addHierarchyListener(hierarchyListener);
            root.addComponentListener(repositionListener);
        }
        if (header instanceof JComponent component && component.getClientProperty(PADDING_KEY) == null) {
            component.setBorder(BorderFactory.createCompoundBorder(component.getBorder(),
                    BorderFactory.createEmptyBorder(0, 0, 0, 14)));
            component.putClientProperty(PADDING_KEY, Boolean.TRUE);
            component.revalidate();
            if (component.getParent() != null) component.getParent().doLayout();
        }
        JLayeredPane layeredPane = root.getLayeredPane();
        if (overlay.getParent() != layeredPane) {
            if (overlay.getParent() != null) overlay.getParent().remove(overlay);
            layeredPane.add(overlay, JLayeredPane.DRAG_LAYER);
        }
        reposition();
        overlay.setVisible(true);
        overlay.repaint();
        return true;
    }

    private void reposition() {
        if (activeHeader == null || overlay.getParent() == null) return;
        JLayeredPane layeredPane = (JLayeredPane) overlay.getParent();
        Point position = SwingUtilities.convertPoint(activeHeader,
                Math.max(0, Math.max(activeHeader.getWidth(), activeHeader.getPreferredSize().width)
                        - dot.getIconWidth() - 3), 2, layeredPane);
        overlay.setBounds(position.x, position.y, dot.getIconWidth(), dot.getIconHeight());
        overlay.repaint();
    }

    private static Tab findTab(Component content) {
        for (Component child = content; child != null && child.getParent() != null; child = child.getParent()) {
            if (child.getParent() instanceof JTabbedPane pane && pane.indexOfComponent(child) >= 0) {
                int index = pane.indexOfComponent(child);
                Component header = pane.getTabComponentAt(index);
                JLabel label = header instanceof JLabel direct ? direct : findLabel(header, pane.getTitleAt(index));
                return new Tab(pane, child, header, label);
            }
        }
        return null;
    }

    private static JLabel findLabel(Component component, String title) {
        if (component instanceof JLabel label && title.equals(label.getText())) return label;
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                JLabel match = findLabel(child, title);
                if (match != null) return match;
            }
        }
        return null;
    }

    private record Tab(JTabbedPane pane, Component page, Component customHeader, JLabel label) {
        Icon icon() {
            if (label != null) return label.getIcon();
            int index = pane.indexOfComponent(page);
            return index < 0 ? null : pane.getIconAt(index);
        }
        void setIcon(Icon icon) {
            if (label != null) label.setIcon(icon);
            else {
                int index = pane.indexOfComponent(page);
                if (index >= 0) pane.setIconAt(index, icon);
            }
            pane.repaint();
        }
    }
}
