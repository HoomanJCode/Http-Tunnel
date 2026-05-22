from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="http-tunnel",
    version="0.1.0",
    author="HTTP Tunnel Contributors",
    description="TCP/UDP over HTTP POST tunnel for restricted networks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/http-tunnel",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.7",
    install_requires=[
        "cryptography>=3.4.7",
        "requests>=2.25.1",
    ],
    entry_points={
        "console_scripts": [
            "http-tunnel-server=http_tunnel.server:run_server",
            "http-tunnel-client=http_tunnel.client:SocksToHttpTunnel.start",
        ],
    },
)
