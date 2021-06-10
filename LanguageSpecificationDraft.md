# Classes
SecurityToken
    Credentials
    Cookies

Resource
    SensitiveFile
    SensitiveInfo

WebServer

User


# Associations


# Attacks

SecurityToken.steal

SecurityToken/Credentials.bruteforce
SecurityToken/Credentials.bypass

SecurityToken/Cookies.mitmSteal         (#SecureFlag)
SecurityToken/Cookies.xssSend           (#HttpOnlyFlag)

Resource/SensitiveFile.idor
Resource/SensitiveInfo.disclosure

WebServer.sqli
WebServer.embeddingInFrame      (#XFrameOptionsEnabled)

User.xss
User.csrf



## Draft
