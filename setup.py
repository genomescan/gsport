import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gsport", # Replace with your own username
    version="1.6.1",
    author="Niels de Water",
    install_requires=['requests==2.22.0'],
    author_email="n.dewater@genomescan.nl",
    description="GSPORT download tool for GenomeScan data from customer portal in command-line interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/genomescan/gsport.git",
    py_modules=['gsport'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "gsport = gsport:main"
        ]
    },
    python_requires='>=3.6',
)
