from setuptools import setup, find_packages

setup(
    name="network-scanner",
    version="0.1.0",
    description="A modern network scanner built with GTK4 and Python",
    author="Julien Grdn",
    author_email="julien@example.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "network_scanner": ["*.py"],
    },
    install_requires=[
        "psutil",
        "PyGObject",
    ],
    entry_points={
        "gui_scripts": [
            "network-scanner=network_scanner.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
)
