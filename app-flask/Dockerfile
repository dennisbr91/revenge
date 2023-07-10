FROM python:3.9-alpine

RUN apk update
RUN apk add libressl-dev musl-dev libffi-dev gcc pcre-dev
RUN addgroup -S app && adduser -S app -G app
ENV HOME /home
ENV APP_HOME $HOME/app
RUN /usr/local/bin/python -m pip install --upgrade pip

WORKDIR $APP_HOME

ADD . .
RUN pip install -r $APP_HOME/all_package.txt
CMD python app.py
RUN chown -R app:app $APP_HOME
USER app