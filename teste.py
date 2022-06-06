import pyotp
import time 
import qrcode
#Generate QR Code

url = pyotp.totp.TOTP('JBSWY3DPEHPK3PXP').provisioning_uri(name='veloso.j04@gmail.com', issuer_name='Secure App')
print(url)

img = qrcode.make(url)
img.save('ola.png')
