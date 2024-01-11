# Converting ntstatus.h into array used in FileTest
import re, sys

def main(argc, argv):

	try:
		# Process the lines in the detections file
		ntstatus_source = 'ntstatus.h'
		file_lines = [line.rstrip('\n') for line in open(ntstatus_source)]

		# Create the deletion script
		f = open('nstatus.cpp', 'wt')

		# Parse all lines
		for single_line in file_lines:

			# Check for lines like "#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth"
			if re.match(r"#define [A-Z_]+ +\(\(NTSTATUS\)0x[0-9a-fA-F]{8}L\)", single_line, re.I):

				# Split the line to words
				word_list = single_line.split(' ')
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
		print("Exception in processing the header file")
		pass

if __name__ == "__main__" :
	main(len(sys.argv), sys.argv)

