from distutils.core import setup

setup(
    name='angr-bf',
    version='0.1',
    description='This is a demonstration of how to extend angr. This module allows for the symoblic exeution of the esoteric language Branfuck.',
    packages=['angr_bf'],
    install_requires=[
        'angr',
        'simuvex',
        'cle',
        'archinfo',
        'pyvex',
    ],
)
