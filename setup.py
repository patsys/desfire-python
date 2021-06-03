from setuptools import setup, find_packages

setup(
	name='DESFfire',
	version='0.11',
	packages=find_packages(exclude=['tests*','examples*']),
	license='MIT',
	description='DESFire library for python',
	long_description=open('README.md').read(),
	install_requires=['pycrypto','enum34','pyscard','pydes','scapy','crcmod'],
	url='https://github.com/patsys/desfire-python',
	author='Patrick Weber',
	author_email='pat.weber91@gmail.com'
)
