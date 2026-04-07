from setuptools import setup, find_packages

setup(
    name="oxytocin-av",
    version="1.0.0",
    author="Your Name",
    author_email="support@oxytocinav.com",
    description="Oxytocin AV — Cross-platform antivirus. Security that feels human.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/oxytocin-av",
    py_modules=["oxytocin_av"],
    python_requires=">=3.8",
    install_requires=[
        "watchdog>=3.0.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "oxytocin-av=oxytocin_av:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
