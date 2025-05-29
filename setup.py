from setuptools import setup, find_packages


setup(
    name="Anubis",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'mss',
        'psutil',
        'pynput',
        'opencv-python',
        'pyperclip',
        'cryptography',
        'pyautogui',
        'pystyle',
        'flask',
    ],
    author="Divine Chukwu",
    author_email="chukwudivineify@gmail.com",
    description="A modular Remote Access Tool (RAT) system",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/dee-engineer/Anubis",
    python_requires=">=3.6",
)