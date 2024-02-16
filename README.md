# blackd

# version
```powershell
$version='1.2.4'
sed -i "s/version = .*/version = '$version'/" pyproject.toml
sed -i "s/blackd-.*-py3-none-any.whl/blackd-$version-py3-none-any.whl/" Dockerfile
```

# publish
```powershell
pdm publish --repository http://pypi.chinx.site:8059/ -u admin
```

# docker build
```bash

cd /mnt/c/python/blackd

cd dist
\cp -f ../Dockerfile .
docker build -t blackd:latest . --no-cache

push_ali blackd:latest
```


# usage
```bash
cd /opt
touch known_first_party

docker rm -f blackd

docker run -d --name=blackd --restart=always -p 45484:45484 \
-v /opt/known_first_party:/opt/known_first_party \
blackd:latest
```