from Crypto import Random
from Crypto.Cipher import AES
import socket

HOST = "127.0.0.1"
PORT = 65432

#vectorul de initializare
IV = b"2406170719992000"


# generez K'=K1  CBC si o criptez
def crypt_generate_K1(key):
	k = Random.get_random_bytes(16)
	print("K1 = ", k)
	cipher = AES.new(key, AES.MODE_CBC, IV)
	return cipher.encrypt(k)


if __name__ == "__main__":
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((HOST, PORT))
		s.listen()

		#connect A & B
		connA, addrA = s.accept()
		connB, addrB = s.accept()

		# cheia K'
		K = Random.get_random_bytes(16)
		print("1. Cheia generata (K) =", K, "\n")
		
		# trimit cheia la B
		with connB:
			print("sunt conectat B", addrB)			
			connB.sendall(K)
			connB.close()		
		with connA:
			print("sunt conectat A", addrA)
			# trimit cheia la A
			connA.sendall(K)
			print("comunicare:", connA.recv(1024))
			# trimit K' lui A
			K1 = crypt_generate_K1(K)
			connA.sendall(K1)			
			connA.close()