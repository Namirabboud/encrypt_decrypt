'''encrypt a file with AES'''
import os
import sys
import random 
import struct
import hashlib
from tkinter import *
from tkinter import ttk
from tkinter import filedialog	
from tkinter import messagebox
from Crypto.Cipher import AES

# PyCrypto block-level encryption API is very low-level
# it expects your key to be either 16, 24 or 32 bytes long
# yo use passwords in different length it is recommended 
# to use SHA-256 digest algorithm from hashlib to generate
# a 32-bytes key from it.

def get_from_string( full_path, option ):
	split = ""
	#on windows
	if "\\" in full_path:
		split = "\\"

	else:
		split = "/"

	if full_path[-1] is '/':
		full_path = full_path[:-1]

	split_list = full_path.split( split )

	if option is "path":
		return full_path.replace( split_list[-1], "" )
	
	if option is "file":
		return split_list[-1]

class App( ttk.Frame ):
	'''	class App deriving from ttk.Frame,
		containing the widgets:
		input file ,
		decrypt and encrypt radio buttons,
		start button when pressed perform 
		the given option on the input file
	'''
	def create_widgets( self ):
		#text variables
		self.file_chosen 	= StringVar()
		self.option			= StringVar()
		self.password		= StringVar()			
			
		#set default value to file_chosen
		self.file_chosen.set( "no file has been chosen!!!" )
		
		#labels
		ttk.Label( self, text="selected file: " ).grid( column=1, row=1  )		
		ttk.Label( self, text="password: " ).grid( column=1, row=2 )
		#entrys
		ttk.Entry( self, textvariable=self.file_chosen ).grid( column=2, row=1, sticky=( W, E ) )
		ttk.Entry( self, textvariable=self.password ).grid( column=2, row=2	)
		#buttons
		ttk.Button( self, text="choose file", command=self.get_file ).grid( column=3, row=1, sticky=( W, E ) )
		ttk.Button( self, text="Start", command=self.start ).grid( column=3, row=3, sticky=( W, E ) )
		
		#radio buttons
		ttk.Radiobutton( self, text='encrypt', variable=self.option,
						 value='encrypt' ).grid( column=2, row=3, sticky=( W ) )
		ttk.Radiobutton( self, text='decrypt', variable=self.option,
					 value='decrypt' ).grid( column=2, row=3, sticky=( E ) )

		for child in self.winfo_children(): child.grid_configure(padx=5, pady=5)

	def get_file( self ):
		#get current dir
		currdir 	= os.getcwd()
		_file 		= filedialog.askdirectory( initialdir=currdir, title="Select file ya doubelll!!!" )
		self.file_chosen.set( _file )

	def start( self ):
		option 	= self.option.get()
		_file	= self.file_chosen.get()
		password= self.password.get()
		error	= ""
	
		if not option:
			error += ", option"

		if not _file or _file in "no file has ben chosen!!!" :
			error += ", file"
	
		if not password:
			error += ", password"

		if error:
			error_string = "Error", error, "was not selected, plz select before you press start ya debe"
			messagebox.showinfo(message= error_string)	
			
		else:
			#get the path where the output should be placed
			path_to = get_from_string( self.file_chosen.get(), 'path' )
			file_chosen  = self.file_chosen.get()
			if option in "encrypt":
				self.encrypt_decrypt( file_chosen, path_to, "encrypt" )
			elif option in "decrypt":
				self.encrypt_decrypt( file_chosen, path_to, "decrypt" )

	def encrypt_decrypt( self, file_chosen, path_to, option="encrypt" ):
		'''	recursive function that encrypt and decrypt files
			if file_chosen rescursively if the file_chosen is
			is a directory. Option define wether decrypt
			or encrypt.
		'''

		file_name		= get_from_string( file_chosen, 'file' )	

		if option in "decrypt":
			out_filename	= os.path.splitext( file_name )[0]
		elif option in "encrypt":
			out_filename 	= file_name + ".enc"
	
		out_file		= os.path.join( path_to, out_filename )

		#base case
		if os.path.isfile( file_chosen ):
			if option in "decrypt":
				#define the out_file where the file should be decrypted
				self.decrypt_file( file_chosen, out_file )
				print( "decrypting", file_chosen )
			elif option in "encrypt":
				self.encrypt_file( file_chosen, out_file )
				print( "encrypting", file_chosen )

		elif os.path.isdir( file_chosen ):
			#create the directory to decrypt inside 
			if not os.path.exists( out_file ):
				os.makedirs( out_file )
			path_to = os.path.join( path_to, out_file )
			
			for _file in os.listdir( file_chosen ):
				_file = os.path.join( file_chosen, _file )
				
				if option in "encrypt ": self.encrypt_decrypt( _file, path_to, "encrypt" )
				else : self.encrypt_decrypt( _file, path_to, "decrypt" )
	
	def decrypt_file( self, in_filename, out_filename ):
		
		chunksize	= 64*1024
		password	= self.password.get()
		#set hash to password and generate a  32 bytes key
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
			
	def encrypt_file( self, in_filename, out_filename ):
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
		
		chunksize	= 64*1024
		password	= self.password.get()
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

	def __init__( self, master=None ):
		ttk.Frame.__init__( self, master )
		self.grid()
		self.create_widgets()
	
if __name__ == "__main__":
	root 	= Tk()
	app 	= App( root )	
	
	root.mainloop()
