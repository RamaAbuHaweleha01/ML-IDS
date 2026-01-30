import os
import sys
sys.path.insert(0, os.path.abspath('../../'))

project = 'ML-Based IDS'
copyright = '2026, Rama Abu-Haweleha'
author = 'Rama Abu-Haweleha'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.autosummary',
]

autosummary_generate = True

templates_path = ['_templates']

exclude_patterns = [
    '_build',
    'ids-env',
    '__pycache__',
    'models',
    'data'
]

language = 'en'

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

