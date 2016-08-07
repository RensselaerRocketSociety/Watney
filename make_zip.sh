#!/usr/bin/env bash
# Zip all the Python files along with the license file
pip install requests -t ./
zip -r Watney *.py LICENSE requests/
rm -rf ./requests*/