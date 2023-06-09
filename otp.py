import time, hashlib, argparse

def getArgs():
	getter = argparse.ArgumentParser(description="Tool for generate a one time password.")
	getter.add_argument('-g', type=str,)
	getter.add_argument('-k', type=str)
	return(getter.parse_args())

def optionk():
      now = int(time.time() // 30)
      converter = hashlib.sha256(str(now).encode('utf-8'))
      hexconvert = converter.hexdigest()[:6]
      result = int(hexconvert, base=16) % 1000000
      print(result)

def optiong(fdin):
      try:
            opener = open(fdin, 'r')
            passwd = opener.read()
      except FileNotFoundError:
            quit("Error: file {} not found".format(fdin))
      except:
            quit("Error: could not read {}".format(fdin))
      if len(passwd) < 64:
            quit("Error: Your password must have 64 characters and you send {}".format(len(passwd)))
      pswdsha256 = hashlib.sha256(passwd.encode('utf-8')).hexdigest()
      pswdmd5 = hashlib.md5(passwd.encode('utf-8')).hexdigest()
      try:
            with open("ft_otp.key", 'w')as openout:
                  openout.write(str(pswdmd5) + str(pswdsha256))
            quit("Key was successfully saved in ft_otp.key")
      except Exception as e:
            quit("Error: {}".format(e))

if __name__ == "__main__":
      arguments = getArgs()
      if arguments.g and arguments.k:
            quit("Error: expected 1 argument not -g and -k")
      if arguments.g:
            optiong(arguments.g)
      if arguments.k:
            try:
                  with open(arguments.k, 'r') as openin:
                        psswd = openin.read()
            except FileNotFoundError:
                  quit("Error: file {} not found".format(arguments.k))
            except:
                  quit("Error: could not read {}".format(arguments.k))
            quit(optionk())


