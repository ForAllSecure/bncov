#!/usr/bin/python3


import platform
import os
import urllib.request


if __name__ == '__main__':
    cur_platform = platform.system()
    if cur_platform == 'Linux':
        download_url = 'https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-Linux-8.0.0-1.tar.gz'
    elif cur_platform == 'Windows':
        download_url = 'https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-Windows-8.0.0-1.zip'
    else:
        print(f'[!] Sorry, Dynamorio is not supported for "{cur_platform}"')
        exit(0)

    download_location = os.path.basename(download_url)
    if download_url.endswith('.zip'):
        extract_cmd = f'unzip {download_location}'
        extracted_dir = download_location[:download_location.rfind('.zip')]
    elif download_url.endswith('.tar.gz'):
        extract_cmd = f'tar xf {download_location}'
        extracted_dir = download_location[:download_location.rfind('.tar.gz')]

    if os.path.exists(extracted_dir):
        print(f'[!] Looks like DynamoRIO is already installed at "{extracted_dir}"')
        exit(0)

    if os.path.exists(download_location):
        print(f'[*] Found expected download file "{download_location}", skipping download')
    else:
        print(f'[*] Downloading DynamoRIO package from {download_url}...')
        urllib.request.urlretrieve(download_url, download_location)
        file_size = os.path.getsize(download_location)
        print(f'[+] Downloaded package to {download_location} ({file_size} bytes)')

    print(f'[*] Extracting with "{extract_cmd}"')
    retval = os.system(extract_cmd)
    print(f'[*] Returncode: {retval}')

    if not os.path.exists(extracted_dir):
        print(f'[!] ERROR: expected extracted dir "{extracted_dir}"')
        exit(0)
    else:
        os.unlink(download_location)
        print(f'[+] DynamoRIO extracted to "{extracted_dir}"')
