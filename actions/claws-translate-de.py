#!/usr/bin/python3
import sys
# https://github.com/ssut/py-googletrans "pip install googletrans==3.1.0a0"
from googletrans import Translator
translator = Translator()

mail = ""
for line in sys.stdin:
	mail += line

translation = translator.translate(mail, dest='de').text

print (translation)

