FROM python:3.6-slim

# prepare directory
WORKDIR /code

# install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# copy app
COPY . .

# run app
CMD ./entrypoint.sh
