FROM node:6 as static_builder
ENV NODE_ENV=development
WORKDIR /app
COPY . /app
RUN npm install -g gulp
RUN npm install gulp
RUN npm install && npm cache clean --force
RUN gulp build
CMD echo "STATIC FILES BUILT"

FROM python:3.6-slim
WORKDIR /code
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
COPY --from=static_builder /app/kqueen_ui/asset/static/ /code/kqueen_ui/asset/static
CMD ./entrypoint.sh
