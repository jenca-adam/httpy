VER=$(python3 -c 'print(__import__("httpy").__version__)')
echo "deploying"
for i in $(dir dist);do echo "moving $i";mv dist/$i official_dist/$i;done
echo "building dist"
python setup.py sdist bdist bdist_wheel
echo "git stuff"
git add --all -v
git commit -m "$VER bump (automated commit)"
git push
clear
echo "========="
echo "IMPORTANT"
echo "========="
echo "Use twine to upload [y*]?" -n
read book
if [ $book == "y" ];then clear;twine upload dist/*.whl "dist/httpy-$VER.tar.gz";fi

