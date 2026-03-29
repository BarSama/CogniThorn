from setuptools import find_packages, setup

setup(
    name="cognithhorn-shared",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pydantic>=2.0",
        "pydantic-settings>=2.0",
        "sqlalchemy>=2.0",
        "asyncpg>=0.29",
        "redis>=5.0",
    ],
)
