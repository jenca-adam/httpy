cd ..
export PYTHONPATH=$PYTHONPATH.
sphinx-apidoc httpy -o source
make html
/opt/google/chrome/chrome build/html/index.html
cd source
