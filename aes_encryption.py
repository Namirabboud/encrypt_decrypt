'''encrypt a file with AES'''
import os
import sys
import random 
import struct
import hashlib
import argparse
from Crypto.Cipher import AES

# PyCrypto block-level encryption API is very low-level
# it expects your key to be either 16, 24 or 32 bytes long
# yo use passwords in different length it is recommended 
# to use SHA-256 digest algorithm from hashlib to generate
# a 32-bytes key from it.

def encrypt_file( password, in_filename, out_filename=None, chunksize=64*1024 ):
	'''	Encrypt file using AES ( CBC mode ) with the given key.
		
		key:
			The encryption key - a string that must be either 16
			24, 32 bytes long. Longer keys are more secure

		in_filename:
			Name of the inpute file

		out_filename:
			If None, '<in_filename>.enc' will be used.

		chunksize:
			sets the size of the chunk wich the function
			uses to read and encrypt the file. Larger chunk
			sizes can be faster for some files and machines
			chunksize must be divisible by 16
	'''
	
	if not out_filename:
		out_filename = in_filename + '.enc'
	
	#set hash to password and generate a  32 bytes key
	m = hashlib.sha256()
	m.update( password.encode( "utf-8" ) )
	key = m.digest()

	iv = ''
	for i in range(16):
		iv += str( random.randint( 0, 9 ) )	

	encryptor	= AES.new( key, AES.MODE_CBC, iv )
	filesize 	= os.path.getsize( in_filename )

	with open( in_filename, 'rb' ) as infile:
		with open( out_filename, 'wb' ) as outfile:
			#write file size as C struct 'Q' is long long C type
			outfile.write( struct.pack( '<Q', filesize ) )
			#stores the ic in the output file
			outfile.write( bytes( iv, 'UTF-8' ) )

			#read the input file chunk by chunk
			while True:
				chunk = infile.read( chunksize )
				#if chunk is null then don't encrypt
				if len( chunk ) == 0:
					break;
				
				# if chunk is less then the wanted size then it's fill with spaces
				elif len( chunk ) % 16 != 0:
					chunk += bytes(' ', 'UTF-8') * ( 16 - len( chunk ) % 16 )

				outfile.write( encryptor.encrypt( chunk ) )

def decrypt_file( password, in_filename, out_filename=None, chunksize=24*1024 ):
	if not out_filename:
		# take the first element in the list
		out_filename = os.path.splitext( in_filename )[0]

	m = hashlib.sha256()
	m.update( password.encode( "utf-8" ) )
	key = m.digest()

	with open( in_filename, 'rb' ) as infile:
		origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]		
		iv = infile.read(16)			
		decryptor = AES.new(key, AES.MODE_CBC, iv)
		
		with open(out_filename, 'wb') as outfile:
			while True:
				chunk = infile.read( chunksize )            	
				if len( chunk ) == 0:
					break
				outfile.write( decryptor.decrypt(chunk) )

			outfile.truncate(origsize)

def ask_file():
	'''	ask the user about the file or dire
		directory he would like to encrypt
		and return the file shosen'''	

	file_type 		= ''
	confirmation	= ''
	file_chosen		= ''

	print( "-> input file or directory you wich to", args.action )
	while True:
		try: 
			file_chosen = input( "" )

		except KeyboardInterrupt:
			sys.exit()
			
		if os.path.isfile( file_chosen ):			
			file_type = 'file'
			break

		elif os.path.isdir( file_chosen ):
			file_type = 'directory'
			break

		else:		
			print( "Error: file", file_chosen," do not exist. \n  check the name of the file or the path entered\n" )
	
	#confirm the user request
	print( "-" * 80 )
	print( "Are you shure you want to", args.action, file_type, file_chosen, "?" )	
	print( "-" * 80 )

	while True:
		try:
			confirmation = input("y(yes)/n(no)\n")
		
		except KeyboardInterrupt:
			sys.exit()

		if confirmation in 'y' or confirmation in 'Y':
			return file_chosen
			
		elif confirmation in 'n' or confirmation in 'N':
			return ask_file()

		else:
			print( "Error: character entered is not valid" )

def ask_password():
	'''get the password as an input  from the user'''

	while True:
		try:
			password = input( "-> enter password \n" )

		except KeyboardInterrupt:
			sys.exit()
		
		if password:
			return password
			break
		
		else:
			print( "no password is being entered" )

def encrypt( full_path , _password_, path_to ):
	'''	recursive function that encrypt files
		if _file_ is a simple file encrypted and 
		return 
		and if the file is a directory encrypt 
		all files and directory recursively
	'''

	file_name 		= get_from_string( full_path, 'file' )
	out_filename 	= file_name + ".enc"
	out_file = os.path.join( path_to, out_filename )

	#base case
	if os.path.isfile( full_path ):
		
		#define the out_file where the file should be encrypted
		encrypt_file( _password_ , full_path, out_file )	
		print( "encrypt file: ", full_path )

	elif os.path.isdir( full_path ):
		# if the file entered is a dir create a dir.enc and encrypt the
		# files in it
		if not os.path.exists( out_file ):
			os.makedirs( out_file )
		path_to = os.path.join( path_to, out_file )

		for path, subdirs, files in os.walk( full_path ):
			for name in files:
				name = os.path.join( full_path, name )
				encrypt( name, _password_ , path_to )
			for directory in subdirs:
				directory = os.path.join( full_path, directory )
				encrypt( directory, _password_ , path_to )

def decrypt( full_path , _password_ , path_to ):
	''' decrypt the file it's pretty
		similar to encrypt function
	'''
	#base case
	file_name 		= get_from_string( full_path, 'file' )
	out_filename = os.path.splitext( file_name )[0]
	out_file = os.path.join( path_to, out_filename )

	#base case
	if os.path.isfile( full_path ):	
		#define the out_file where the file should be encrypted
		decrypt_file( _password_ , full_path, out_file )	
		print( "encrypt file: ", full_path )

	elif os.path.isdir( full_path ):
		# if the file entered is a dir create a dir.enc and encrypt the
		# files in it
		if not os.path.exists( out_file ):
			os.makedirs( out_file )
		path_to = os.path.join( path_to, out_file )

		for path, subdirs, files in os.walk( full_path ):
			for name in files:
				name = os.path.join( full_path, name )
				decrypt( name, _password_ , path_to )
			for directory in subdirs:
				directory = os.path.join( full_path, directory )
				decrypt( directory, _password_ , path_to )

	
def get_from_string( full_path, option ):

	if full_path[-1] is '/':
		full_path = full_path[:-1]

	split_list = full_path.split( "/" )

	if option is "path":
		return full_path.replace( split_list[-1], "" )
	
	if option is "file":
		return split_list[-1]

				
if __name__ == "__main__":

	parser = argparse.ArgumentParser()
	parser.add_argument( '--encrypt', '-e', dest='action', action='store_const', const='encrypt', default='encrypt',
						help='choose the encrypt file action (default is encrypt)' )
	parser.add_argument( '--decrypt', '-d', dest='action', action='store_const', const='decrypt' )
	args = parser.parse_args()	

	file_chosen = ask_file()
	password	= ask_password()

	path_to 	= get_from_string( file_chosen, 'path' )

	if args.action is 'encrypt':
		encrypt( file_chosen, password, path_to )	 

	elif args.action is 'decrypt':
		decrypt( file_chosen, password, path_to )
