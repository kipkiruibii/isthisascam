import pyclamd
from django.core.files.uploadedfile import UploadedFile

# Initialize ClamAV client
cd = pyclamd.ClamdUnixSocket()  # or ClamdNetworkSocket(host='localhost', port=3310) for network socket


def scan_file(file: UploadedFile) -> bool:
    '''
    scans file for viruses.
    :param file: image file
    :return: bool. True if file is clean
    '''
    # Ensure the file is readable
    file.seek(0)
    file_content = file.read()

    # Scan the file content
    result = cd.scan_stream(file_content)

    # Determine the result
    if result is None:
        return True
    else:
        print(f"Malware detected: {result}")
        # report/blacklist the ip
        return False
