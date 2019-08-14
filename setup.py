import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="emlog",
    version="0.0.1",
    author="Carlton Shepherd",
    author_email="carlton@linux.com",
    description="An implementation of the Emlog system for building tamper-resistant, integrity-protected message sequences",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/carltonshepherd/emlog",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Intended Audience :: Science/Research",
        "Development Status :: 3 - Alpha"
    ],
    keywords='emlog,tamper,resistant,logging,integrity,protection,crypto,cryptography,security',
    install_requires=[
        "cryptography>=0.5",
    ]
)