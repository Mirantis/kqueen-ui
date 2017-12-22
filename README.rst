KQueen UI - UI for Kubernetes cluster manager
=============================================

.. image:: https://travis-ci.org/atengler/kqueen-ui.svg?branch=master
    :target: https://travis-ci.org/atengler/kqueen-ui

.. image:: https://readthedocs.org/projects/kqueen-ui/badge/?version=latest
    :target: http://kqueen-ui.readthedocs.io/en/latest/

Overview
--------

UI project for Mirantis KQueen, more informations in KQueen repository `here <https://github.com/Mirantis/kqueen>`_.

Development
-----------

-  Bootstrap kqueen-ui environment. You need running KQueen backend app to connect to, to run it, please refer to KQueen project documentation.

::

    mkvirtualenv -p /usr/bin/python3 kqueen-ui
    pip3 install -e ".[dev]"
    pip3 install --editable .
    npm install
    npm install -g gulp
    gulp build
    # optionally start mail server container
    docker-compose -f docker-compose.mail.yml up -d
    python -m kqueen_ui

Configuration
-------------

We load configuration from file ``config/dev.py`` by default and this
can be configured by ``KQUEENUI_CONFIG_FILE`` environment variable. Any
environment variable matching name ``KQUEENUI_*`` will be loaded and saved
to configuration.

Documentation
-------------

For full documenation please refer to
`kqueen-ui.readthedocs.io <http://kqueen-ui.readthedocs.io>`__.

DEMOs
-----

**Generic KQueen Overview**

.. image:: https://img.youtube.com/vi/PCAwCxPQc2A/0.jpg
   :target: https://www.youtube.com/watch?v=PCAwCxPQc2A&t=1s

**AKS (Azure) in KQueen**

.. image:: https://img.youtube.com/vi/xHydnJGcs2k/0.jpg
   :target: https://youtu.be/xHydnJGcs2k
