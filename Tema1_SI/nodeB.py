from Crypto.Cipher import AES
import socket


# cunosc vectorul de initializare
IV = b"2406170719992000"
HOST = "127.0.0.1"
PORT = 65432
PORT2 = 54321


class nodeB:
  def __init__(self, key):
    self.K = key

  def set_communication_mode(self, m):
    self.mode = m

  def crypt_decript(self, key):
    cipher = AES.new(self.K, AES.MODE_CBC, IV)
    self.K1 = cipher.decrypt(key)
    print("Decripted key =", self.K1)

  def get_communication_mode(self):
    return self.mode


  def set_operator(self, op):
    self.operator = op


  def crypt_decript(self, k):
    cipher = AES.new(self.K, AES.MODE_CBC, IV)
    self.K1 = cipher.decrypt(k)
    print("Cheia criptata =", self.K1)


  @staticmethod
  def _unpad(s):
      return s[:-ord(s[len(s)-1:])]


  def decrypt(self, block):
    if self.mode == b'CFB':
      plain = int.from_bytes(self.K1, byteorder="big") ^ int.from_bytes(self.operator, byteorder="big")
      plain = int.from_bytes(block, byteorder="big") ^ plain
      self.set_operator(plain.to_bytes(max(len(self.operator), len(block)), byteorder="big"))
      plain = plain.to_bytes(max(len(self.operator), len(block)), byteorder="big")
    else: # ecb
      plain = int.from_bytes(self.K1, byteorder="big") ^ int.from_bytes(block, byteorder="big")
      plain = plain.to_bytes(max(len(self.operator), len(block)), byteorder="big")
      self.set_operator(block)

    return self._unpad(plain).decode("utf-8")


if __name__ == "__main__":
  global node_B

  # comunicare KEY MANAGER
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    K = s.recv(1024)
    print(" Cheia privata (K) :", K, "\n")

    node_B = nodeB(K)

    s.shutdown(socket.SHUT_RDWR)
    s.close()
  
  # comunicare NODE A
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT2))
    s.listen()
    conn, addr = s.accept()

    with conn:
      print("Nodul A", addr, "s-a conectat.")
      data = conn.recv(1024)

      start_communication = ""
      while start_communication != "ok":
        start_communication = input("START=> `ok` <<< ")
      conn.sendall(b"ok")

      print("Modul de comunicare :", data, "\n")
      node_B.set_communication_mode(data)

      print("Cheia criptata :", "\n")
      data = conn.recv(1024)
      node_B.crypt_decript(data)
      node_B.set_operator(IV)

      plain_text = ""

      while True:
        data = conn.recv(1024)

        if not data:
          break

        # decriptez de la A
        plain_text += str(node_B.decrypt(data))

      # afisez tot
      print("\nPlain text =", plain_text, "\n")