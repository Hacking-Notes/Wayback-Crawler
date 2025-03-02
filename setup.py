from setuptools import setup, find_packages

setup(
    name="wayback_crawler",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.5",
        "rich>=13.5.2",
        "tqdm>=4.66.1",
        "aiofiles>=23.2.1",
        "pydantic>=2.3.0",
        "typer>=0.9.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "wayback-crawler=wayback_crawler.__main__:app",
        ],
    },
    python_requires=">=3.8",
    author="Alexis",
    description="A tool for discovering and analyzing subdomains using Wayback Machine data",
) 