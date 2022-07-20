from setuptools import setup

setup(
    name="dissect.vmfs",
    packages=["dissect.vmfs"],
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
)
