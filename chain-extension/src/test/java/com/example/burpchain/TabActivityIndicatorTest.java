package com.example.burpchain;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TabActivityIndicatorTest {
    @Test void blinksOnCustomTabLabelAndRestoresItsIcon() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane tabs = new JTabbedPane();
            JPanel page = new JPanel();
            JPanel content = new JPanel();
            page.add(content);
            tabs.addTab("Requests Chainer", page);
            JLabel label = new JLabel("Requests Chainer");
            Icon original = new Icon() {
                @Override public int getIconWidth() { return 4; }
                @Override public int getIconHeight() { return 4; }
                @Override public void paintIcon(Component c, Graphics g, int x, int y) {
                    g.setColor(Color.GRAY);
                    g.fillRect(x, y, 4, 4);
                }
            };
            label.setIcon(original);
            tabs.setTabComponentAt(0, label);

            TabActivityIndicator indicator = new TabActivityIndicator();
            assertTrue(indicator.show(content, true));
            assertNotSame(original, label.getIcon());
            assertNull(tabs.getIconAt(0));
            assertTrue(indicator.show(content, false));
            assertSame(original, label.getIcon());
        });
    }

    @Test void fallsBackToTabbedPaneIconWhenThereIsNoCustomLabel() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JTabbedPane tabs = new JTabbedPane();
            JPanel page = new JPanel();
            tabs.addTab("Requests Chainer", page);
            TabActivityIndicator indicator = new TabActivityIndicator();
            assertTrue(indicator.show(page, true));
            assertNotNull(tabs.getIconAt(0));
            assertTrue(indicator.show(page, false));
            assertNull(tabs.getIconAt(0));
        });
    }

    @Test void customTextTabUsesOverlayWithoutReplacingCloseButton() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JRootPane root = new JRootPane();
            JTabbedPane tabs = new JTabbedPane();
            JPanel page = new JPanel();
            JPanel content = new JPanel();
            page.add(content);
            tabs.addTab("Requests Chainer", page);
            JPanel header = new JPanel();
            header.add(new JTextField("Requests Chainer"));
            JLabel close = new JLabel("x");
            Icon closeIcon = new Icon() {
                @Override public int getIconWidth() { return 4; }
                @Override public int getIconHeight() { return 4; }
                @Override public void paintIcon(Component c, Graphics g, int x, int y) {}
            };
            close.setIcon(closeIcon);
            header.add(close);
            tabs.setTabComponentAt(0, header);
            root.getContentPane().add(tabs);
            root.setSize(500, 300);
            root.doLayout();
            tabs.doLayout();
            int before = root.getLayeredPane().getComponentCount();
            int headerWidth = header.getPreferredSize().width;

            TabActivityIndicator indicator = new TabActivityIndicator();
            assertTrue(indicator.show(content, true));
            assertEquals(headerWidth + 14, header.getPreferredSize().width);
            Component dot = root.getLayeredPane().getComponent(0);
            int closeRight = SwingUtilities.convertPoint(close, close.getWidth(), 0,
                    root.getLayeredPane()).x;
            assertTrue(dot.getX() >= closeRight);
            assertTrue(indicator.show(content, true));
            assertEquals(headerWidth + 14, header.getPreferredSize().width);
            assertEquals(before + 1, root.getLayeredPane().getComponentCount());
            assertSame(closeIcon, close.getIcon());
            assertEquals(10, dot.getWidth());
            assertEquals(10, dot.getHeight());
            assertTrue(indicator.show(content, 0.5f));
            BufferedImage faded = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
            Graphics fadedGraphics = faded.getGraphics();
            dot.paint(fadedGraphics);
            fadedGraphics.dispose();
            int alpha = faded.getRGB(5, 5) >>> 24;
            assertTrue(alpha >= 100 && alpha <= 150);
            assertTrue(indicator.show(content, true));
            BufferedImage image = new BufferedImage(10, 10, BufferedImage.TYPE_INT_ARGB);
            Graphics graphics = image.getGraphics();
            dot.paint(graphics);
            graphics.dispose();
            assertEquals(0xE8752A, image.getRGB(5, 5) & 0xFFFFFF);
            assertTrue(indicator.show(content, false));
            assertEquals(before, root.getLayeredPane().getComponentCount());
        });
    }
}
