from distutils.core import setup

setup(
    name='angr_platforms',
    version='0.1',
    description='A collection of extra platforms for angr',
    packages=['angr_platforms'],
    install_requires=[
        'angr',
        'cle',
        'archinfo',
        'pyvex',
        'clint'
    ],
)
