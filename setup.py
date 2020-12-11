
import setuptools

setuptools.setup(name='bottle-cas-python3',
      version='3.0.0',
      description='A fork of bottle-cas package supporting python3',
      author='Bruno Ilponse',
      url='http://github.com/brunoilponseisae/bottle-cas',
      packages=['bottle_cas'],
      python_requires='>=3.6',
      install_requires=['bottle', 'beaker', 'requests'],)
