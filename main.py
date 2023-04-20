import sys, imp, json, os, subprocess
from base64 import b64encode, b64decode
from javax import swing
from java.util import ArrayList
from burp import IBurpExtender
from burp import IMessageEditorTabFactory, IMessageEditorController, IContextMenuFactory
from burp import IMessageEditorTab, ITab
from burp import IParameter
from java.awt import Component, BorderLayout
from java.awt.event import ActionListener
from java.io import PrintWriter, File
from javax.swing.table import DefaultTableModel
from javax.swing import JPanel, JTable, BoxLayout, JSplitPane, JButton, JFileChooser, JTextField, JFrame, JLabel, JScrollPane, JTabbedPane, JOptionPane

PLUGINS_DIR = "/tmp/plugins/" # REPLACE THIS WITH YOUR OWN PLUGIN DIR
PYTHON_PATH = "/usr/local/bin/python3" # REPLACE THIS WITH YOUR OWN PYTHON3 PATH IF THIS DOESN'T WORK


ret_function_d_text = None
script_path = PLUGINS_DIR
request_list = []


def decryptData(body, req_headers=None, headers=None):
    # NOTE: Experimental - Trying to load scripts using subprocess instead of imp.
    if script_path == PLUGINS_DIR:
        return "No module selected!"
    try:
        with open("/tmp/burp_decrypter_data.txt", "w") as fd:
            fd.write(b64encode(body) + " | " + b64encode(str([x for x in req_headers])))
        cmd = "%s %s d" % (PYTHON_PATH, script_path)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out, err = proc.communicate()
        print(out.decode(), err.decode())
    except Exception as e:
        print(e)
    return out.decode()
    

def encryptData(body, req_headers=None, headers=None):
    # NOTE: Experimental - Trying to load scripts using subprocess instead of imp.
    if script_path == PLUGINS_DIR:
        return "No module selected!"
    with open("/tmp/burp_decrypter_data.txt", "w") as fd:
            fd.write(b64encode(body) + " | " + b64encode(str([x for x in req_headers])))
    cmd = "%s %s e" % (PYTHON_PATH, script_path)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = proc.communicate()
    print(out.decode(), err.decode())
    return out.decode()
    

ret_function_d = decryptData
ret_function_e = encryptData

class BurpExtender(IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorController, IContextMenuFactory):
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Decrypter")
        self.tmpFileData = ''
        self._splitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        _verticalSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        _verticalSplitPane.setDividerLocation(70)
        self._requestViewer = callbacks.createMessageEditor(self, True)
        self.logTable = Table(self, self._requestViewer)
        scrollPane = JScrollPane(self.logTable)
        button = JButton("Refresh Modules", actionPerformed=self.refreshModules)
        button.setSize(100, 100)
        _verticalSplitPane.setRightComponent(scrollPane)
        _verticalSplitPane.setLeftComponent(button)
        self._splitpane.setLeftComponent(_verticalSplitPane)
        self._splitpane.setRightComponent(self._requestViewer.getComponent())
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self.logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.addSuiteTab(self)
        return        
    
    def refreshModules(self, event):
        self.logTable.updateTable()
    
    def dummy_ret(self, text, request_headers=None, headers=None):
        return "No module selected."            
    
    def createNewInstance(self, controller, editable):
        global ret_function_e, ret_function_d, ret_function_d_text
        if ret_function_e == None or ret_function_d == None:
            ret_function_e = self.dummy_ret
            ret_function_d = self.dummy_ret
            ret_function_d_text = self.dummy_ret
        return Base64InputTab(self, controller, editable)
    
    def getTabCaption(self):
        return "Decrypter"
    
    def getUiComponent(self):
        return self._splitpane
    

class Base64InputTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        global request_list
        
        self._extender = extender
        self._editable = editable
        self._controller = controller
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self.write = self._extender.stdout.println
        self.headers = None
        self.modifiedBody = None

    def getTabCaption(self):
        return "Decrypted Data"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()
        
    def isEnabled(self, content, isRequest):
        return True
        
    def setMessage(self, content, isRequest):
        global ret_function_e, ret_function_d
        if content is None:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            req = self._extender._helpers.analyzeRequest(content)
            method = req.getMethod()
            self.headers = req.getHeaders()
            mod_body = ""
            if isRequest:
                request = self._extender._helpers.analyzeRequest(self._controller.getRequest())
                self.request_headers = request.getHeaders()
                body = self._extender._helpers.bytesToString(content[req.getBodyOffset():len(content)])
                mod_body = ret_function_d(body, self.request_headers, self.headers)
            else:
                request = self._extender._helpers.analyzeRequest(self._controller.getResponse())
                request1 = self._extender._helpers.analyzeRequest(self._controller.getRequest())
                self.request_headers = request1.getHeaders()
                # self.request_headers = request.getHeaders()
                body = self._extender._helpers.bytesToString(content[req.getBodyOffset():len(content)])
                mod_body = ret_function_d(body, self.request_headers, self.headers)
            self._txtInput.setText(mod_body.strip("\n"))
            self._txtInput.setEditable(self._editable)
        self._currentMessage = content
    
    def getMessage(self):
        global ret_function_e, ret_function_d
        if self._txtInput.isTextModified():
            text = self._txtInput.getText()
            text = self._extender._helpers.bytesToString(text)
            mod_text = ret_function_e(text, self.request_headers)
            print("MOD_TEXT", mod_text)
            return self._extender._helpers.buildHttpMessage(self.headers, mod_text.strip("\n"))
            # return self._currentMessage
        else:
            return self._currentMessage
    
    def isModified(self):
        return self._txtInput.isTextModified()
    
    def getSelectedData(self):
        print("Selected data: ", self._txtInput.getSelectedText())
        return self._txtInput.getSelectedText()
      
class Table(JTable):
    def __init__(self, extender, requestViewer):
        self._extender = extender
        self._requestViewer = requestViewer
        cols = ['Module List']
        self.data = []
        dataModel = DefaultTableModel(self.data, cols)
        self.setModel(dataModel)
        
    def updateTable(self):
        files = os.listdir(PLUGINS_DIR)
        print("Files in ", PLUGINS_DIR)
        print(files)
        cols = ["Module List"]
        self.data = [[x] for x in files if "." in x and x.split(".")[1] == 'py']
        print(self.data)
        dataModel = DefaultTableModel(self.data, cols)
        self.setModel(dataModel)
        self.repaint()
    
    def changeSelection(self, row, col, toggle, extend):
        global ret_function_d, ret_function_e, ret_function_d_text, script_path
        logEntry = self.data[row]
        print("Selected: ", logEntry[0])
        script_path = PLUGINS_DIR + logEntry[0]
        JTable.changeSelection(self, row, col, toggle, extend)
