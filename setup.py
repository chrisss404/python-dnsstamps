import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dnsstamps",
    version="1.4.0",
    author="Christian Hofer",
    author_email="chrisss404@gmail.com",
    description="Create and parse DNS stamps with ease.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chrisss404/python-dnsstamps",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    scripts=['bin/dnsstamp.py'],
)
