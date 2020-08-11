# -*- coding: utf-8 -*-
import sys
import os
import requests
import json
import base64
import hashlib
import subprocess
import getpass
import re
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
class CommonHelper:
	def __init__(self):
		pass
	@staticmethod
	def readQss(style):
		with open(style, 'r') as f:
			return f.read()
class TabDemo(QTabWidget):
	def __init__(self, parent=None):
		super(TabDemo, self).__init__(parent)
		#os.environ["vtshell"] = os.getcwd()+"\\bin"
		#os.system("setx WORK1 "+os.getcwd()+"\\bin")
		self.AppLog = QTextEdit()
		self.AppLog.append("应用启动")
		self.resize(700, 500)
		self.tab1 = QWidget()
		self.tab2 = QWidget()
		self.tab3 = QWidget()
		self.tab4 = QWidget()
		self.tab5 = QWidget()

		self.addTab(self.tab1, "Tab 1")
		self.addTab(self.tab2, "Tab 2")
		self.addTab(self.tab3, "Tab 3")
		self.addTab(self.tab4, "Tab 4")
		self.addTab(self.tab5, "Tab 5")

		self.tab1UI()
		self.tab2UI()
		self.tab3UI()
		self.tab4UI()
		self.tab5UI()

		self.setWindowTitle("Vegetable工具箱")
		self.setWindowIcon(QIcon('logo.ico'))
	def tab1UI(self):
		layout = QGridLayout()
		self.EncryptPan = QTextEdit()
		self.DecryptPan = QTextEdit()
		self.EncryptButton = QPushButton()
		self.DecryptButton = QPushButton()
		self.CryptType = QComboBox()
		self.itemDelegate = QStyledItemDelegate()
		self.CryptType.setItemDelegate(self.itemDelegate)
		self.CryptType.addItems(["base64","base16","base32"])
		self.CryptType.addItem("md5")
		self.CryptType.addItems(["sha256","sha1","sha384","sha512"])
		self.EncryptButton.setText("加密>")
		self.DecryptButton.setText("<解密")
		self.EncryptButton.clicked.connect(self.doEncrypt)
		self.DecryptButton.clicked.connect(self.doDecrypt)
		layout.addWidget(self.EncryptPan, 0, 0, 7, 3)
		layout.addWidget(self.CryptType, 0, 4, 1, 1)
		layout.addWidget(self.EncryptButton, 2, 4, 1, 1)
		layout.addWidget(self.DecryptButton, 4, 4, 1, 1)
		layout.addWidget(self.DecryptPan, 0, 5, 7, 3)
		self.setTabText(0, "加密解密")
		self.tab1.setLayout(layout)
	def tab2UI(self):
		layout = QGridLayout()
		self.RequestType = QComboBox()
		self.itemDelegate2 = QStyledItemDelegate()
		self.RequestType.setItemDelegate(self.itemDelegate2)
		self.RequestType.addItems(["POST","GET", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE"])
		layout.addWidget(self.RequestType, 0, 0)
		self.UrlBox = QLineEdit()
		layout.addWidget(self.UrlBox, 0, 1, 1, 4)
		self.RetHeaders = QTextEdit()
		self.RetHeaders.setReadOnly(True)
		self.RetHeaders.setPlaceholderText("返回Headers(json格式)")
		self.RetMessage = QTextEdit()
		self.RetMessage.setReadOnly(True)
		self.RetMessage.setPlaceholderText("返回数据")
		self.RequestButton = QPushButton()
		self.RequestButton.setText("请求")
		self.RequestButton.clicked.connect(self.doRequest)
		layout.addWidget(self.RequestButton, 0, 5)
		#layout.addWidget(QLabel("请求Headers"), 1, 0, 1, 3)
		#layout.addWidget(QLabel("请求数据"), 1, 3, 1, 3)
		self.RequestHeaders = QTextEdit()
		self.RequestData = QTextEdit()
		self.RequestHeaders.setPlaceholderText("请求Headers(json格式)")
		self.RequestData.setPlaceholderText("请求数据(json格式)")
		layout.addWidget(self.RequestHeaders, 1, 0, 3, 3)
		layout.addWidget(self.RequestData, 1, 3, 3, 3)
		layout.addWidget(self.RetHeaders, 4, 0, 5, 3)
		layout.addWidget(self.RetMessage, 4, 3, 5, 3)
		self.setTabText(1, "HTTP请求")
		self.tab2.setLayout(layout)
	def tab3UI(self):
		layout = QGridLayout()
		self.commandHint = QLabel()
		self.commandLine = QLineEdit()
		self.commandLine.returnPressed.connect(self.runShell)
		self.commandMain = QTextEdit()
		self.commandMain.setReadOnly(True)
		layout.addWidget(self.commandHint, 1, 0, 1, 2)
		layout.addWidget(self.commandLine, 1, 2, 1, 4)
		layout.addWidget(self.commandMain, 2, 0, 8, 6)
		self.InitShellPutHead(v=0)
		self.setTabText(2, "Shell")
		self.tab3.setLayout(layout)
	def tab4UI(self):
		layout = QGridLayout()
		layout.addWidget(self.AppLog, 0, 0)
		self.setTabText(3, "应用日志")
		self.tab4.setLayout(layout)
	def tab5UI(self):
		layout = QFormLayout()
		layout.addRow(QLabel("此项目由vt-dev-team编写，使用GPL v2协议开源"))
		self.LicenseText = QTextEdit()
		#self.LicenseText.setReadOnly(True)
		f = open("LICENSE", "r")
		LICENSEVIEW = f.read()
		f.close()
		self.LicenseText.setPlainText(LICENSEVIEW)
		layout.addRow(self.LicenseText)
		self.setTabText(4, "关于项目")
		self.tab5.setLayout(layout)
	def doEncrypt(self):
		CType = self.CryptType.currentText()
		if CType == "base64":
			self.DecryptPan.setPlainText(bytes.decode(base64.b64encode(self.EncryptPan.toPlainText().encode('utf-8'))))
		elif CType == "base16":
			self.DecryptPan.setPlainText(bytes.decode(base64.b16encode(self.EncryptPan.toPlainText().encode('utf-8'))))
		elif CType == "base32":
			self.DecryptPan.setPlainText(bytes.decode(base64.b32encode(self.EncryptPan.toPlainText().encode('utf-8'))))
		elif CType == "md5":
			hobject = hashlib.md5()
			hobject.update(self.EncryptPan.toPlainText().encode('utf-8'))
			self.DecryptPan.setPlainText(hobject.hexdigest())
		elif CType == "sha256":
			hobject = hashlib.sha256()
			hobject.update(self.EncryptPan.toPlainText().encode('utf-8'))
			self.DecryptPan.setPlainText(hobject.hexdigest())
		elif CType == "sha1":
			hobject = hashlib.sha1()
			hobject.update(self.EncryptPan.toPlainText().encode('utf-8'))
			self.DecryptPan.setPlainText(hobject.hexdigest())
		elif CType == "sha384":
			hobject = hashlib.sha384()
			hobject.update(self.EncryptPan.toPlainText().encode('utf-8'))
			self.DecryptPan.setPlainText(hobject.hexdigest())
		elif CType == "sha512":
			hobject = hashlib.sha512()
			hobject.update(self.EncryptPan.toPlainText().encode('utf-8'))
			self.DecryptPan.setPlainText(hobject.hexdigest())
		self.AppLog.append("用"+CType+"加密")
	def doDecrypt(self):
		CType = self.CryptType.currentText()
		try:
			if CType == "base64":
				self.EncryptPan.setPlainText(bytes.decode(base64.b64decode(self.DecryptPan.toPlainText().encode('utf-8'))))
			elif CType == "base16":
				self.EncryptPan.setPlainText(bytes.decode(base64.b16decode(self.EncryptPan.toPlainText().encode('utf-8'))))
			elif CType == "base32":
				self.EncryptPan.setPlainText(bytes.decode(base64.b32decode(self.EncryptPan.toPlainText().encode('utf-8'))))
			elif CType == "md5":
				raise RuntimeError('md5无法解密')
		except:
			QMessageBox.critical(self, '出错了','密文无法解密',QMessageBox.Ok)
		self.AppLog.append("用"+CType+"解密")
	def InitShellPutHead(self, v=1):
		nowcwd = os.getcwd()
		nowUser = getpass.getuser()
		self.commandHint.setText("<font color=green>"+nowUser+"</font>:<font color=blue>"+nowcwd+"</font>$ ")
		if v != 1:
			self.commandMain.setText("VegeTable Shell [Version 1.0.2008.1931]\n(c) vt-dev-team.All Rights Reserved.\n")
	def runShell(self):
		nowcwd = os.getcwd()
		nowUser = getpass.getuser()
		commandHead = "<font color=green>"+nowUser+"</font>:<font color=blue>"+nowcwd+"</font>$ "
		command = self.commandLine.text()
		self.commandMain.append(commandHead + command)
		if command == "clear":
			self.commandMain.clear()
		mytask = subprocess.Popen(command, shell=True,stdin=subprocess.PIPE, stdout=subprocess.PIPE, 		stderr=subprocess.STDOUT)
		while mytask.poll() is None:
			line = mytask.stdout.readline()
			line = line.decode('gb2312').strip()
			if line:
				self.commandMain.append(line)
		searchObj = re.match( r'cd (.*)', command, re.M|re.I)
		if searchObj:
			os.chdir(searchObj.group(1))
		self.commandLine.setText("")
		self.InitShellPutHead()
		self.AppLog.append("运行命令"+command)
	def doRequest(self):
		RType = self.RequestType.currentText()
		try:
			if len(self.RequestHeaders.toPlainText()) == 0:
				ReqHeaders={}
			else:
				ReqHeaders = json.loads(self.RequestHeaders.toPlainText())
			if len(self.RequestData.toPlainText()) == 0:
				ReqData={}
			else:
				ReqData = json.loads(self.RequestHeaders.toPlainText())
			if RType == "GET":
				r = requests.get(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "POST":
				r = requests.post(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "HEAD":
				r = requests.head(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "PUT":
				r = requests.put(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "DELETE":
				r = requests.delete(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "CONNECT":
				r = requests.connect(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "OPTIONS":
				r = requests.options(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			elif RType == "TRACE":
				r = requests.trace(url=self.UrlBox.text(), headers=ReqHeaders, data=ReqData)
			self.RetHeaders.setPlainText(json.dumps(json.loads(str(r.headers).replace("'","\"")), sort_keys=True, indent=4, separators=(',', ':')))
			self.RetMessage.setPlainText(r.text)
		except:
			QMessageBox.critical(self, '出错了','请求失败',QMessageBox.Ok)
		self.AppLog.append("使用"+RType+"请求")
if __name__ == '__main__':
	app = QApplication(sys.argv)
	demo = TabDemo()
	qssStyle = CommonHelper.readQss("style.qss")
	demo.setStyleSheet(qssStyle)
	demo.show()
	sys.exit(app.exec_())