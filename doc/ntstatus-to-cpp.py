import os, sys

def main(argc, argv):

	try:
		# Process the lines in the detections file
		ntstatus_source = 'ntstatus.h'
		file_lines = [line.rstrip('\n') for line in open(ntstatus_source)]

		# Create the deletion script
		f = open('nstatus.cpp', 'wt')

		# Parse all lines
		for line in file_lines:

			# Skip lines that begin with
			if(line.startswith('#define ')):

				# Split the line to words
				word_list = line.split(' ')
				if(len(word_list) >= 2):

					# Avoid lines like "NTSTATUS_FROM_WIN32(x)"
					ntstatus_name = word_list[1]
					if(ntstatus_name.find('(') != -1):
						continue

					# Write the second word to the output file
					f.write('    DEFINE_NTSTATUS_ENTRY(%s),\n' % ntstatus_name)
					print(ntstatus_name)

		# Close the delete file
		f.close()

	except:
		print "Exception in processing the file list"
		pass

if __name__ == "__main__" :
	main(len(sys.argv), sys.argv)
