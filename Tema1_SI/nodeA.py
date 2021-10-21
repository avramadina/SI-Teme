from Crypto.Cipher import AES


import socket


#vectorul de initializare
IV = b"2406170719992000"
HOST = '127.0.0.1'
PORT = 65432
PORT2 = 54321

class nodA:
  def __init__(self, key):
    self.K = key

  def set_communication_mode(self, m):
    self.mode = m

  def get_communication_mode(self):
    return self.mode
  
  def set_operator(self, op):
    self.operator = op

  def decript_key(self, k):
    cipher = AES.new(self.K AES.MODE_CBC, IV)
    self.private_key = cipher.decrypt(k)

  def _pad(self, s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

  def encrypt(self, block):
    block = '{}'.format(self._pad(block)).encode()
    if self.mode == b'CFB':  
      cript = int.from_bytes(self.operator, byteorder="big") ^ int.from_bytes(self.private_key, byteorder="big")
      cript = cript ^ int.from_bytes(block, byteorder="big")
      cript = cript.to_bytes(max(len(self.operator), len(block)), byteorder="big")
      self.set_operator(cript)
    else: # ecb
      cript = int.from_bytes(block, byteorder="big") ^ int.from_bytes(self.private_key, byteorder="big")
      cript = cript.to_bytes(max(len(self.operator), len(block)), byteorder="big")
      self.set_operator(cript)
    return cript

if __name__ == "__main__":
  #KEY MANAGER
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    K = s.recv(1024)
    print(" Cheia privata (K):", K, "\n")

    nodeA = nodA(K)

    print(" Comunicare:CFD/ECB:")
    mode = input()
    print()

    if mode.lower() == "ECB":
      s.sendall(b"ECB")
      nodeA.set_communication_mode(b"ECB")
    else:
      s.sendall(b"CFB")
      nodeA.set_communication_mode(b"CFB")

    mode = mode.encode()

    K1 = s.recv(1024)
    print(" Cheia criptata =", K1, "\n")
    
    nodeA.set_operator(IV)
    nodeA.decript_key(K1)

    s.shutdown(socket.SHUT_RDWR)
    s.close()
  #  NODE B
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s2:
    s2.connect((HOST, PORT2))
    s2.sendall(mode)   
    # comunicare ok
    print("4. Confirmare =", s2.recv(1024), "\n")
    s2.sendall(private_key)
    file = open('/home/adina/Desktop/tema1_SI/text.txt')
    while True:
      block = file.read(16)
      if not block:
        break
      print("Citire:", block)
      criptare = nodeA.encrypt(block)
      # trimit la B
      print("Blocul criptat:", criptare)
      s2.sendall(criptare)