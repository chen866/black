FROM python:3.11-alpine3.18

WORKDIR /opt

RUN cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone  \
    && pip install http://pypi.chinx.site:8059/packages/blackd-1.2.3-py3-none-any.whl -i https://pypi.tuna.tsinghua.edu.cn/simple/ --no-cache-dir --disable-pip-version-check

EXPOSE 45484

CMD python -m blackd
