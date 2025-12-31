import hashlib

flag = 0

psw_hash = input("Enter md5 Hash: ")

wordlist = input("File name: ")

try:
	psw_file = open (wordlist, "r")
except Exception as e:
	print("No file found")
	quit()

for word in psw_file:

	enc_wrd = word.encode('utf-8')  
	digest = hashlib.md5(enc_wrd.strip()).hexdigest()

   
	# print(word)
	#print(digest)


	if digest == psw_hash:
		print("Password Found")
		print("Password is :\t " + word)
		flag = 1
		break

if flag == 0:
    print("Password/passphrase is not in the list")		