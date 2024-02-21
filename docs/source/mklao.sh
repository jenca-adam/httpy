cd ..
export PYTHONPATH=$PYTHONPATH.
sphinx-apidoc httpy -o source
make html
firefox build/html/index.html
cd source
