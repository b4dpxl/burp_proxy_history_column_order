"""
Perist the order of columns in the Proxy HTTP History tab

History:
1.0.0: First version
"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "1.0.0"

import json
import traceback

from burp import IBurpExtender, IExtensionStateListener

# Java imports
from java.awt import Frame
from javax import swing


NAME = "Proxy HTTP History Column Order"

SETTING_ORDER = "SETTING_ORDER"

DEFAULT_POSITIONS = [
    '#',
    'Host',
    'Method',
    'URL',
    'Params',
    'Edited',
    'Status',
    'Length',
    'MIME type',
    'Extension',
    'Title',
    'Comment',
    'TLS',
    'IP',
    'Cookies',
    'Time',
    'Listener port'
]


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            self._callbacks.printError("\n\n*** PYTHON EXCEPTION")
            self._callbacks.printError(traceback.format_exc(e))
            self._callbacks.printError("*** END\n")
            # raise
    return wrapper

class BurpExtender(IBurpExtender, IExtensionStateListener):

    _callbacks = None
    _helpers = None
    _proxy_history = None
    _history_table = None

    def registerExtenderCallbacks(self, callbacks):
        # for error handling

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(NAME)

        for frame in Frame.getFrames():
            self._find_proxy_history(frame)
        if not self._proxy_history:
            print("ERROR: Unable to locate HTTP History tab")
            return

        history_panel = self._proxy_history.getComponentAt(1).getComponent(1)  # component 0 is the filter
        scroll_panel = history_panel.getComponent(0)
        if scroll_panel.getComponent(0).getComponent(0).getName() == "proxyHistoryTable":
            self._history_table = scroll_panel.getComponent(0).getComponent(0)
        
        else:
            print("Unable to locate HTTP History table")
            return

        burp_frame = None
        # TODO work with popped out Proxy window
        for frame in Frame.getFrames():
            if frame.isVisible() and frame.getTitle().startswith("Burp Suite"):
                print("Got burp frame")
                burp_frame = frame

                bar = burp_frame.getJMenuBar()

                self._menu = swing.JMenu("Proxy History Columns")

                save_menu = swing.JMenuItem("Save Order", actionPerformed=self.save_positions)
                save_menu.setToolTipText("Save the current column order")

                self.load_menu = swing.JMenuItem("Load Order", actionPerformed=self.load_positions)
                self.load_menu.setToolTipText("Load the saved column order")
                
                reset_menu = swing.JMenuItem("Reset Order", actionPerformed=self.reset_positions)
                reset_menu.setToolTipText("Reset the column order to the default")

                clear_menu = swing.JMenuItem("Clear Order", actionPerformed=self.clear_positions)
                clear_menu.setToolTipText("Remove the saved column order")

                self._menu.add(save_menu)
                self._menu.add(self.load_menu)
                self._menu.add(reset_menu)
                self._menu.add(clear_menu)

                bar.add(self._menu, bar.getMenuCount())
                bar.repaint()
                print("Added menu")

        self.load_positions()

        callbacks.registerExtensionStateListener(self)

    @fix_exception
    def extensionUnloaded(self):
        self.reset_positions()
        bar = self._menu.getParent()
        bar.remove(self._menu)
        bar.repaint()
        print("Unloaded " + NAME)

    @fix_exception
    def _find_proxy_history(self, container):
        if container.getComponents() and self._proxy_history is None:
            for c in container.getComponents():
                try:
                    if c.getTabCount > 0:
                        for x in range(c.getTabCount()):
                            if c.getTitleAt(x) == "Proxy":
                                self._proxy_history = c.getComponentAt(x)
                                return
                except:
                    pass
                self._find_proxy_history(c)

    @fix_exception
    def save_positions(self, event):
        self._callbacks.saveExtensionSetting(SETTING_ORDER, json.dumps(self._get_current_positions()))
        swing.JOptionPane.showMessageDialog(None, "Order saved")
        self.load_menu.setEnabled(True)
        print("Saved orders")

    @fix_exception
    def load_positions(self, event=None):
        s_positions = self._callbacks.loadExtensionSetting(SETTING_ORDER)
        if s_positions:
            try:
                positions = json.loads(s_positions.decode())
                print("Loaded positions")
                self._set_positions(positions)
                self.load_menu.setEnabled(True)
                return True
            except:
                self._callbacks.printError("Unable to decode positions")
        self.load_menu.setEnabled(False)
        return False

    @fix_exception
    def reset_positions(self, event):
        print("Resetting")
        self._set_positions(DEFAULT_POSITIONS)
        pass

    @fix_exception
    def clear_positions(self, event):
        print("Clearing")
        self._callbacks.saveExtensionSetting(SETTING_ORDER, "")
        self.load_menu.setEnabled(False)
        swing.JOptionPane.showMessageDialog(None, "Saved order cleared")

    @fix_exception
    def _get_current_positions(self):
        x = []
        for i,c in enumerate(self._history_table.getColumnModel().getColumns()):
            x.append(c.getHeaderValue())
        return x

    def _set_positions(self, positions):
        columns = {}
        model = self._history_table.getColumnModel()
        for c in model.getColumns():
            columns[c.getHeaderValue()] = c

        while model.getColumnCount():
            model.removeColumn(model.getColumn(0))

        for c in positions:
            model.addColumn(columns.get(c))
