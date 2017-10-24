# KQueen UI - Kubernetes cluster manager Flask frontend

## Development

### Backend

* Bootstrap environment

```
mkvirtualenv -p /usr/bin/python3 venv
pip3 install -r requirements.txt
pip3 install --editable .
kqueen_ui
```

### Frontend

* Prepare JS building environment

```
npm install
```

* Build static resources

```
gulp build
```

* Start local development server with auto-restart

```
gulp dev
```


## Configuration

We load configuration from file `config/dev.py` by default and this can be configured by `KQUEEN_CONFIG_FILE` environment varialbe.

| Configuration option | Type | Default value | Description |
| --- | --- | --- | --- |
| `KQUEEN_CONFIG_FILE` | Environment variable | `config/dev.py` | Configuration file to load |

## Documentation

For full documenation please refer to [kqueen-ui.readthedocs.io](http://kqueen-ui.readthedocs.io).
