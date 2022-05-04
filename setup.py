from setuptools import setup, find_packages

with open("README.md", "r") as readme_file:
    readme = readme_file.read()

requirements = []

setup(
    name="dsram",
    version="1.0.3",
    author="Walter Haydock",
    author_email="walter@deploy-securely.com",
    description="A quantitative cyber risk management calculator",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/Deploying-Securely/DSRAM",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=['License :: OSI Approved :: Apache Software License'],
)
