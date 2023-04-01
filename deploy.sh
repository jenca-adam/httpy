echo "deploying"
for i in $(dir dist);do echo "moving $i";mv dist/$i official_dist/$i;done
echo "building dist"
python setup.py sdist bdist bdist_wheel
echo "git stuff"
git add --all -v
git commit -m "$(python3 -c 'print(__import__("httpy").__version__)')"
git push
